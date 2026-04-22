module example.com/echo-demo

go 1.22

require (
	github.com/Tzam-St/tzam-go v0.0.0
	github.com/labstack/echo/v4 v4.12.0
)

// While the package is unpublished, point to the local path. Drop this
// replace directive after the first release to github.com/Tzam-St/tzam-go.
replace github.com/Tzam-St/tzam-go => ../..
