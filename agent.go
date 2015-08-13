package heka_enhanced_tcp_input

import (
	"net"
)

type Agent interface {
	AnswerSuccess() (bts []byte, err error)
	AnswerError(error) (bts []byte, err error)
	Init(cfg map[string]interface{}, addr *net.TCPAddr) error
}
