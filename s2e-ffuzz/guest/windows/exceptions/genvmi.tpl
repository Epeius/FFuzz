{% for d in data %}
g_vmi_modules["_{{d.checksum}}"] = {
      name = "{{ d.name }}",
      version = "6.2.9200.16384",
      checksum = {{ d.checksum }},
      nativebase = {{ d.nativebase | hex }},
      symbols = {
        {%- for f,a in d.symbols.iteritems() %}
            {{f}} = {{a | hex}},
        {% endfor %}
      }
}
{% endfor %}
