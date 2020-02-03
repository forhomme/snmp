// Package snmp implements low-level support for SNMP with focus in SNMP
// agents.
//
// At the encoding level it uses the PromonLogicalis/asn1 to parse and
// serialize SNMP messages providing Go types for that.
//
// The package also provides transport-independent support for creating custom
// SNMP agents with small footprint.
//
// A example of a simple SNMP UDP agent:
//
//	package main
//
//	import (
//		"log"
//		"net"
//		"time"
//
//		"github.com/PromonLogicalis/asn1"
//		"github.com/PromonLogicalis/snmp"
//	)
//
//	func main() {
//		agent := snmp.NewAgent()
//
//		// Set the read-only and read-write communities
//		agent.SetCommunities("publ", "priv")
//
//		// Register a read-only OID.
//		since := time.Now()
//		agent.AddRoManagedObject(
//			// sysUpTime
//			asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3, 0},
//			func(oid asn1.Oid) (interface{}, error) {
//				seconds := int(time.Now().Sub(since) / time.Second)
//				return seconds, nil
//			})
//
//		// Register a read-write OID.
//		name := "example"
//		agent.AddRwManagedObject(
//			// sysName
//			asn1.Oid{1, 3, 6, 1, 2, 1, 1, 5, 0},
//			func(oid asn1.Oid) (interface{}, error) {
//				return name, nil
//			},
//			func(oid asn1.Oid, value interface{}) error {
//				strValue, ok := value.(string)
//				if !ok {
//					return snmp.VarErrorf(snmp.BadValue, "invalid type")
//				}
//				name = strValue
//				return nil
//			})
//
//		// Bind to an UDP port
//		addr, err := net.ResolveUDPAddr("udp", ":161")
//		if err != nil {
//			log.Fatal(err)
//		}
//		conn, err := net.ListenUDP("udp", addr)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		// Serve requests
//		for {
//			buffer := make([]byte, 1024)
//			n, source, err := conn.ReadFrom(buffer)
//			if err != nil {
//				log.Fatal(err)
//			}
//
//			buffer, err = agent.ProcessDatagram(buffer[:n])
//			if err != nil {
//				log.Println(err)
//				continue
//			}
//
//			_, err = conn.WriteTo(buffer, source)
//			if err != nil {
//				log.Fatal(err)
//			}
//		}
//	}
//
package snmp

// TODO Support for traps
// TODO More flexible ACL and authentication mechanism.
// TODO Use the origin to process ACLs and authentication.
// TODO Support for SNMPv2.

import (
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"sort"

	"github.com/PromonLogicalis/asn1"
)

// Getter is a function called to return a managed object value.
type Getter func(oid asn1.Oid) (interface{}, error)

// Setter is a function called to set a managed object value.
type Setter func(oid asn1.Oid, value interface{}) error

// Agent is a transport independent engine to process SNMP requests.
type Agent struct {
	Log      *log.Logger
	Ctx      *asn1.Context
	Handlers []ManagedObject
	Public   string
	Private  string
}

// NewAgent create and initialize an agent.
func NewAgent() *Agent {
	a := &Agent{Ctx: Asn1Context()}
	a.SetLogger(nil)
	a.SetCommunities("public", "private")
	return a
}

// SetLogger defines the logger used for internal messages.
func (a *Agent) SetLogger(logger *log.Logger) {
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}
	a.Log = logger
	a.Ctx.SetLogger(logger)
}

// SetCommunities defines the public and private communities.
func (a *Agent) SetCommunities(public, private string) {
	a.Public, a.Private = public, private
}

// checkCommunity handles "authentication" and acls
func (a *Agent) CheckCommunity(community string) (rw bool, err error) {

	// Access check. Right now only read-only community is implemented
	if community != a.Public && community != a.Private {
		// The agent should ignore invalid communities
		err = fmt.Errorf("invalid community \"%s\"", community)
		return
	}

	// Super complex ACLs
	if community == a.Private {
		rw = true
	}
	return
}

// AddRoManagedObject registers a read-only managed object.
func (a *Agent) AddRoManagedObject(oid asn1.Oid, getter Getter) error {
	return a.AddRwManagedObject(oid, getter, nil)
}

// AddRwManagedObject registers a read-write managed object.
//
// The inteface{} values returned by a Getter or received by a Setter must be
// of one of the following types:
//
//	int
//	string
//	asn1.Null
//	asn1.Oid
//	snmp.Counter32
//	snmp.Counter64
//	snmp.IpAddress
//	snmp.Opaque
//	snmp.TimeTicks
//	snmp.Unsigned32
//
func (a *Agent) AddRwManagedObject(oid asn1.Oid, getter Getter,
	setter Setter) error {

	if getter == nil {
		return fmt.Errorf("a managed object should have at least a getter")
	}
	if setter == nil {
		setter = func(oid asn1.Oid, value interface{}) error {
			return VarErrorf(NotWritable, "OID %s is not writable", oid)
		}
	}
	if a.GetManagedObject(oid, false) != nil {
		return fmt.Errorf("OID %d is already registered", oid)
	}
	h := ManagedObject{oid, nil, getter, setter}
	a.Handlers = append(a.Handlers, h)
	sort.Sort(SortableManagedObjects(a.Handlers))
	return nil
}

// managedObject represents a registered managed object.
type ManagedObject struct {
	Oid asn1.Oid
	// TODO Add type check inside the agent processing.
	Typ reflect.Type
	Get Getter
	Set Setter
}

// sortableManagedObjects is a helper type to sort managed objects slices.
type SortableManagedObjects []ManagedObject

func (h SortableManagedObjects) Len() int      { return len(h) }
func (h SortableManagedObjects) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h SortableManagedObjects) Less(i, j int) bool {
	return h[i].Oid.Cmp(h[j].Oid) < 0
}

// getManagedObject returns the exact managed object for the given OID when
// next=false  or the next object when next=true.
func (a *Agent) GetManagedObject(oid asn1.Oid, next bool) *ManagedObject {
	for _, h := range a.Handlers {
		cmp := oid.Cmp(h.Oid)
		if (!next && cmp == 0) || (next && cmp < 0) {
			return &h
		}
		if !next && cmp < 0 {
			break
		}
	}
	return nil
}

// ProcessMessage handles a SNMP Message.
func (a *Agent) ProcessMessage(request *Message) (response *Message, err error) {
	// SNMPv1 only for now
	if request.Version == 3 {
		// Discard SNMPv2 messages
		err = fmt.Errorf("invalid SNMP version %d", request.Version)
		return
	}

	rw, err := a.CheckCommunity(request.Community)
	if err != nil {
		return
	}

	// Dispatch each type of PDU
	a.Log.Printf("request: %#v\n", request)
	var res GetResponsePdu
	switch pdu := request.Pdu.(type) {
	case GetRequestPdu:
		res = a.ProcessPdu(Pdu(pdu), false, false)
	case GetNextRequestPdu:
		res = a.ProcessPdu(Pdu(pdu), true, false)
	case SetRequestPdu:
		if rw {
			res = a.ProcessPdu(Pdu(pdu), false, true)
		} else {
			res = GetResponsePdu(pdu)
			res.ErrorIndex = 1
			res.ErrorStatus = NoSuchName
		}
	default:
		// SNMPv2 PDUs are ignored
		err = fmt.Errorf("PDU not supported: %T", request.Pdu)
		return
	}

	// Copy request
	copy := *request
	response = &copy

	// Set response
	response.Pdu = res
	a.Log.Printf("response: %#v\n", response)
	return
}

// ProcessDatagram handles a binany SNMP message.
func (a *Agent) ProcessDatagram(requestBytes []byte) (responseBytes []byte, err error) {
	// Decode message. Invalid messages are discarded
	request := Message{}
	ctx := Asn1Context()
	remaining, err := ctx.Decode(requestBytes, &request)
	if err != nil {
		return
	}
	if len(remaining) > 0 {
		err = fmt.Errorf("%d remaining bytes.\n", len(remaining))
		return
	}

	// Process message
	response, err := a.ProcessMessage(&request)
	if err != nil {
		return
	}

	responseBytes, err = ctx.Encode(*response)
	return
}

// processPdu handles SNMPv1 requests with exception of SnmpV1TrapPdu.
func (a *Agent) ProcessPdu(pdu Pdu, next bool, set bool) GetResponsePdu {

	// Keep returned values in a separated slice for a Get request
	var variables []Variable

	var err error
	res := GetResponsePdu(pdu)
	for i, v := range pdu.Variables {
		a.Log.Printf("oid: %s\n", v.Name)
		// Retrieve the managed object
		h := a.GetManagedObject(v.Name, next)
		if h == nil {
			res.ErrorIndex = i + 1
			res.ErrorStatus = NoSuchName
			return res
		}
		// Set or get the value
		var value interface{}
		if set {
			err = h.Set(h.Oid, v.Value)
		} else {
			value, err = h.Get(h.Oid)
		}
		if err != nil {
			res.ErrorIndex = i + 1
			if e, ok := err.(VarError); ok {
				res.ErrorStatus = e.Status
			} else {
				res.ErrorStatus = GenErr
			}
			return res
		}
		// Values returned by a Get are kept in a separated list. If an error
		// occurs the original list of variables should be returned.
		if !set {
			variables = append(variables, Variable{h.Oid, value})
		}
	}
	if !set {
		// Update all values, since all variables were processed without error:
		res.Variables = variables
	}
	return res
}

func (a *Agent) ProcessBulkPdu(bulkpdu BulkPdu, next bool, set bool) GetBulkRequestPdu {

	// Keep returned values in a separated slice for a Get request
	var variables []Variable

	res := GetBulkRequestPdu(bulkpdu)
	for _, v := range bulkpdu.Variables {
		a.Log.Printf("oid: %s\n", v.Name)
		h := a.GetManagedObject(v.Name, next)
		if h == nil {
			return res
		}

		// get value
		var value interface{}
		value, err := h.Get(h.Oid)
		if err != nil {
			log.Fatalf("Error : ", err)
		}
		variables = append(variables, Variable{h.Oid, value})
	}
	res.Variables = variables
	return res
}

// VarError is an error type that can be returned by a Getter or a Setter. When
// VarError is returned, it Status is used in the SNMP response.
type VarError struct {
	Status  int
	Message string
}

var _ error = VarError{}

func (e VarError) Error() string {
	return fmt.Sprintf("%s (status: %d)", e.Message, e.Status)
}

// VarErrorf creates a new Error with a formatted message.
func VarErrorf(status int, format string, values ...interface{}) VarError {
	return VarError{
		Status:  status,
		Message: fmt.Sprintf(format, values...),
	}
}
