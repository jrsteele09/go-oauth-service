package server

func (s *Server) initRoutes() {
	s.uiHandlers.InitRoutes(s.RegisterRouteHandler)
	s.oauth2Handlers.InitRoutes(s.RegisterRouteHandler)
}
