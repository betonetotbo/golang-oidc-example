package html

import (
	"html/template"
	"net/http"
)

func RenderTemplate(w http.ResponseWriter, r *http.Request, name string, model any) error {
	tpl, err := template.ParseFiles("web/template/" + name + ".html")
	if err != nil {
		return err
	}

	data := make(map[string]any)
	for k, v := range r.Header {
		data[k] = v[0]
	}
	if model != nil {
		data["model"] = model
	}

	return tpl.Execute(w, data)
}
