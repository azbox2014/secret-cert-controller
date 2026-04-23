{{- define "secret-cert-controller.name" -}}
secret-cert-controller
{{- end }}

{{- define "secret-cert-controller.fullname" -}}
{{ .Release.Name }}-secret-cert-controller
{{- end }}