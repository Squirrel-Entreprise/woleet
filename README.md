Wrapper for woleet.io API
====

```
func ComputeSHA256Hash(filePath string) (string, error)
func VerifySignature(r *http.Request, secret string) (bool, error)
type Anchor struct{ ... }
type CreateAnchorPayload struct{ ... }
type Metadata struct{ ... }
type Pageable struct{ ... }
type Search struct{ ... }
type Sort struct{ ... }
type Status string
    const WAIT Status = "WAIT" ...
type Woleet struct{ ... }
    func New(authToken string) *Woleet
```