package heka_enhanced_tcp_input

var agents = make(map[string]func() interface{})

func RegisterAgent(name string, fn func() interface{}) {
	agents[name] = fn
}
