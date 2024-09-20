# golang-oidc-example

Example about how to integrate Keycloak OIDC protocol with golang/go-chi.

## Running local

```bash
make up
```

This will start:
* Keycloak server at http://localhost:8080
  * Admin console http://localhost:8080/admin (user admin, password admin)
  * **You will need to access the admin area, select the "my-realm" realm and add some user to it**
* Sample app at http://localhost:8080