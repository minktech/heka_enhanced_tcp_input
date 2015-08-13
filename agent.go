package heka_enhanced_tcp_input

type Agent interface {
	AnswerSuccess() (bts []byte, err error)
	AnswerError(error) (bts []byte, err error)
}
