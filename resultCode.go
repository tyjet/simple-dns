package main

// ResultCode for DNS looking
type ResultCode int

// Enumeration of result codes
const (
	NOERROR = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

func (resultCode ResultCode) String() string {
	return [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}[resultCode]
}
