
# MayHost Panel

MayHost Panel es un panel web desarrollado con Node.js que ofrece una interfaz para administración, gestión de archivos, terminal web y más. Este proyecto está pensado para ser un sistema liviano y rápido para manejar usuarios y recursos desde una interfaz sencilla.

## 🚀 Características

- Panel de administración accesible vía navegador.
- Gestor de archivos visual. [BETA]
- Páginas HTML integradas.

## 📂 Estructura del proyecto

```
MayHost-Panel/
├── Dockerfile               # Define cómo crear el contenedor del panel
├── index.js                 # Servidor backend principal (Node.js + Express)
├── package.json             # Dependencias y scripts
└── public/                  # Archivos estáticos accesibles desde el navegador
    ├── 404.html             # Página de error personalizada
    ├── admin.html           # Panel administrativo
    ├── file_manager.html    # Explorador de archivos
    ├── index.html           # Página principal/login
    └── terminal.html        # Terminal estilo shell
```

## 🛠️ Instalación

### Node.js local
```bash
git clone https://github.com/SoySapo6/MayHost-Panel.git
cd MayHost-Panel
npm install
node index.js
```

Accede en tu navegador a `http://localhost:3000`

---

## 🧠 Autor

Hecho por SoyMaycol <3

Licencia: MIT LICENCE

---

✨ Hecho con amor y código por Maycol (⁠◍⁠•⁠ᴗ⁠•⁠◍⁠)⁠❤
