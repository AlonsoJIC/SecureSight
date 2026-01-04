# SecureSight Backend

Analizador de seguridad web pasivo y ético. Evalúa headers, cookies, HTTPS, información expuesta y genera un score de seguridad.

## Uso como API REST

1. Instala dependencias:
```bash
pip install -r requirements.txt
```

2. Inicia el backend:
```bash
python app.py
```

3. Envía un POST a http://localhost:5000/analyze con:
```json
{
  "url": "https://ejemplo.com"
}
```

## Módulos
- Headers de seguridad
- Cookies
- HTTPS y certificado
- Información expuesta
- Sistema de scoring

## Requisitos
- Python 3.7+
- requests
- flask

## Ignorar en git
Ver archivo `.gitignore` para excluir entorno virtual y archivos temporales.
