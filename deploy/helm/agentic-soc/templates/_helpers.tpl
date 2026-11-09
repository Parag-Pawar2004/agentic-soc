{{- define "soc.name" -}}{{ .Release.Name }}{{- end -}}
{{- define "soc.labels" -}}
app.kubernetes.io/part-of: agentic-soc
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "soc.secretName" -}}
{{- if .Values.existingSecret }}{{ .Values.existingSecret }}{{ else }}{{ .Release.Name }}-secrets{{ end -}}
{{- end -}}
{{- define "soc.image" -}}
{{ .root.Values.image.registry }}/{{ .root.Values.image.owner }}/agentic-soc-{{ .component }}:{{ .root.Values.image.tag }}
{{- end -}}
