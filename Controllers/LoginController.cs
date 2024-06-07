using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using projecto_net.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace projecto_net.Controllers
{
    public class LoginController : Controller
    {
        // defino una llave para poder encryotar y desincriptar de igual forma poder usarlo en otro dispositivo para mantener la configuracion 
        private readonly string encryptionKey = "cifrado_desincri";
        //uso el contexto de la base de datos para poder crear el login 
        private readonly MercyDeveloperContext _context;

        public LoginController(MercyDeveloperContext context)
        {
            _context = context;
        }

        public IActionResult Registro()
        {
            return View(new Registro());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        //realizo el proceso de registro de usuario 
        public async Task<IActionResult> RegistroAsync(Registro registro)
        {
            if (registro.Correo == null || registro.Password == null)
            {
                ViewData["mensaje"] = "Correo y contraseña son obligatorios.";
                return View();
            }

            var usuarioExistente = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == registro.Correo);
            if (usuarioExistente != null)
            {
                ViewData["mensaje"] = "El correo ya está registrado.";
                return View();
            }
            //lo uso para encryptar y desincrpytar antes de guardarla y despues recuperarla en la base de datos 
            //toma la contrañsea que esa sin encryptar para pasarselo al metodo encryptstring y cifrarla  en mi caso utilizando el tripledes 
            string claveEncriptada = EncryptString(registro.Password);
            //hace lo mismo pero agarrando la clave encryptada para luego liberarla utilizando el mismo metodo tripledes ,de hecho se puede hacer con bycrypt pero no me resulto :C
            string claveDesencriptada = DecryptString(claveEncriptada);
            //creo los atributos del nuevo usuario para luego subirlo y guardarlo en la base de datos 
            Usuario usuario = new Usuario()
            {
                Nombre = registro.Nombre,
                Apellido = registro.Apellido,
                Correo = registro.Correo,
                Password = claveEncriptada // Guardo la contraseña encryptada en la base de datos usando la llave 
            };

            await _context.Usuarios.AddAsync(usuario);
            await _context.SaveChangesAsync();

            if (usuario.Id != 0)
            {
                return RedirectToAction("Index", "Login");
            }
            else
            {  //muestro si resulta un error , en caso de algun parametro mal o un error en la base de datos 
                ViewData["mensaje"] = "Hubo un error al registrar el usuario.";
                return View();
            }
        }

        public IActionResult Index()
        {
            return View(new Login());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]//proceso para el login 
        public async Task<IActionResult> Index(Login login, AuthenticationProperties Properties)
        {//verifico si el ususario ya se encuentra en la base de datos comparando sus parametros ,
            Usuario? usuario_encontrado = await _context.Usuarios.FirstOrDefaultAsync(u => u.Correo == login.Correo && u.Password == EncryptString(login.Password));

            if (usuario_encontrado == null)
            {
                ViewData["mensaje"] = "Correo o contraseña incorrectos.";
                return View();
            }
            //metodo de auntenticacion usando cookies  
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, usuario_encontrado.Nombre ?? string.Empty),
                new Claim(ClaimTypes.Email, usuario_encontrado.Correo ?? string.Empty),
                new Claim(ClaimTypes.Anonymous, usuario_encontrado.Password ?? string.Empty)
            };

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            AuthenticationProperties properties = new AuthenticationProperties();

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                properties
            );

            return RedirectToAction("Index", "Home");
        }

        // Método el cual es para encryptar todos los textos usando tripleDES
        public string EncryptString(string plainText)
        {
            byte[] iv = new byte[8];
            using (var des = TripleDES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes(encryptionKey);
                des.IV = iv;
                var encryptor = des.CreateEncryptor();
                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }

        // Método donde desincryptamos usando tripleDES
        public string DecryptString(string encryptedText)
        {
            byte[] iv = new byte[8];
            using (var des = TripleDES.Create())
            {
                des.Key = Encoding.UTF8.GetBytes(encryptionKey);
                des.IV = iv;
                var decryptor = des.CreateDecryptor();
                byte[] bytes = Convert.FromBase64String(encryptedText);
                return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }
    }
}
