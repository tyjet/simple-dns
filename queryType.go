package main

// QueryType represents the class of record in the DNS response
type QueryType int

// QueryType enumerations
const (
	UNKNOWN QueryType = iota
	A       QueryType = 1
	NS      QueryType = 2
	CNAME   QueryType = 5
	MX      QueryType = 15
	AAAA    QueryType = 28
)

func (queryType QueryType) String() string {
	switch queryType {
	case A:
		return "A"
	case NS:
		return "NS"
	case CNAME:
		return "CNAME"
	case MX:
		return "MX"
	case AAAA:
		return "AAAA"
	default:
		return "UNKNOWN"
	}
}
