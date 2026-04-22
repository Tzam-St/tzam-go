module example.com/gin-demo

go 1.22

require (
	github.com/Tzam-St/tzam-go v0.0.0
	github.com/gin-gonic/gin v1.10.0
)

// While the package is unpublished, point to the local path. Drop this
// replace directive after the first release to github.com/Tzam-St/tzam-go.
replace github.com/Tzam-St/tzam-go => ../..
