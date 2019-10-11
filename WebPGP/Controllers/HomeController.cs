using System.IO;
using System.Web.Mvc;
using WebPGP.Util.OpenPgp;

namespace WebPGP.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(FormCollection form)
        {
            string privateKey;
            string publicKey;

            KeyGenerator.GenerateKeys(
                form["UserName"],
                form["PassPhrase"],
                out publicKey,
                out privateKey);

            ViewBag.UserName = form["UserName"];
            ViewBag.PassPhrase = form["PassPhrase"];
            ViewBag.PrivateKey = privateKey;
            ViewBag.PublicKey = publicKey;

            return View();
        }

        public ActionResult Encrypt()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Encrypt(FormCollection form)
        {
            string inputPath = form["InputFilePath"];
            FileInfo inputFileInfo = new FileInfo(inputPath);

            string outputPath = Path.Combine(Path.GetTempPath(), inputFileInfo.Name + ".gpg");

            Encryptor.Encrypt(inputPath, form["PublicKey"], form["PrivateKey"], form["PassPhrase"], outputPath);

            return Content(outputPath);
        }

        public ActionResult Decrypt()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Decrypt(FormCollection form)
        {
            string inputPath = form["InputFilePath"];
            FileInfo inputFileInfo = new FileInfo(inputPath);

            string outputPath = Path.Combine(Path.GetTempPath(), inputFileInfo.Name.Replace(".gpg", ""));

            Decryptor.Decrypt(inputPath, form["PrivateKey"], form["PassPhrase"], outputPath);

            return Content(outputPath);
        }
    }
}