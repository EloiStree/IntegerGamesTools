using System;
using System.Drawing;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using NBitcoin.Secp256k1;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

using SixLabors.ImageSharp.Processing;


class Program
{
    static async Task Main(string[] args)
    {
        string privateRSAKeyPEM="";
        string publicRSAKeyPEM = "";
        string privateKeyEthereum = "";
        string publicKeyEthereum = "";
        string address = "";
        string privateRsaKeyXml = "";
        string publicRsaKeyXml = "";

        //Read a file name PrivateKey.txt and PublicKey.txt
        string path = Directory.GetCurrentDirectory();
        Console.WriteLine("Hello :) \n\n");
        if (File.Exists("KeyPair/Private/RSA_PRIVATE_XML.txt"))
        {
            Console.WriteLine("You already have a private key generated, here:\n" + path);
            Console.WriteLine("");

            privateRsaKeyXml = File.ReadAllText("KeyPair/Private/RSA_PRIVATE_XML.txt"); 
            publicRsaKeyXml = File.ReadAllText("KeyPair/Public/RSA_PUBLIC_XML.txt"); 
            
            privateRSAKeyPEM = File.ReadAllText("KeyPair/Private/RSA_PRIVATE_PEM.txt"); 
            publicRSAKeyPEM = File.ReadAllText("KeyPair/Public/RSA_PUBLIC_PEM.txt");

            privateKeyEthereum = File.ReadAllText("KeyPair/Private/ETH_PRIVATE.txt");
            publicKeyEthereum = File.ReadAllText("KeyPair/Public/ETH_PUBLIC.txt");
            address =  File.ReadAllText("KeyPair/Public/ETH_ADDRESS.txt");

        }
        else
        {

            Console.WriteLine("Start creating key pair RSA & Ethereum, here:\n" + path);
            Console.WriteLine("\n\n\n");

            Directory.CreateDirectory("KeyPair");
            Directory.CreateDirectory("KeyPair/Private");
            Directory.CreateDirectory("KeyPair/Public");

            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 1024;

                privateRsaKeyXml    = rsa.ToXmlString(true);
                publicRsaKeyXml     = rsa.ToXmlString(false);
                File.WriteAllText("KeyPair/Private/RSA_PRIVATE_XML.txt", privateRsaKeyXml);
                File.WriteAllText("KeyPair/Private/0_DONT_SHARE.txt", "DONT SHARE YOUR PRIVATE KEY TO ANYONE");
                File.WriteAllText("KeyPair/Private/1_DONT_OPEN_DURING_STREAM.txt", "DONT OPEN THIS FILE AS A STREAMER");
                File.WriteAllText("KeyPair/Private/2_DONT_PUT_ON_GITHUB.txt", "OBVIOUSLY DONT PUT THOSE FILE ON GITHUB");
                
                File.WriteAllText("KeyPair/Public/RSA_PUBLIC_XML.txt", publicRsaKeyXml);


                privateRSAKeyPEM  = rsa.ExportRSAPrivateKeyPem();
                publicRSAKeyPEM     = rsa.ExportRSAPublicKeyPem();


                File.WriteAllText("KeyPair/Private/RSA_PRIVATE_PEM.txt", privateRSAKeyPEM);
                File.WriteAllText("KeyPair/Public/RSA_PUBLIC_PEM.txt", publicRSAKeyPEM);



                var ecKey = EthECKey.GenerateKey();

                privateKeyEthereum   = ecKey.GetPrivateKeyAsBytes().ToHex();
                publicKeyEthereum    = ecKey.GetPubKey().ToHex();
                address              = ecKey.GetPublicAddress();

                File.WriteAllText("KeyPair/Private/ETH_PRIVATE.txt", privateKeyEthereum);
                File.WriteAllText("KeyPair/Public/ETH_PUBLIC.txt", publicKeyEthereum);
                File.WriteAllText("KeyPair/Public/ETH_ADDRESS.txt", address);
                File.WriteAllText("KeyPair/Public/ETH_SCAN.url", $"[InternetShortcut]\nURL = https://etherscan.io/address/{address}");

                Identicon icon = new Identicon(address, 8, 5);
                icon.SavePng("KeyPair/Public/ETH_ICON.png");

                // PEM TO XML
                //string xmlPrivateKey = PemToXmlConverter.ConvertPrivateKey(publicPrivateKeyPEM);
                //string xmlPublicKey = PemToXmlConverter.ConvertPublicKey(publicOnlyKeyPEM);
                //File.WriteAllText("PrivateKeyTest.txt", xmlPrivateKey);
                //File.WriteAllText("PublicKeyTest.txt", xmlPublicKey);


            }
        }
        Console.WriteLine("\n\n >>> Never share your private key. <<< \n\n");

        //string privateKey = File.ReadAllText("KeyPair/Private/RSA_PRIVATE_XML.txt");
        string publicKey = File.ReadAllText("KeyPair/Public/RSA_PUBLIC_XML.txt");

        Console.WriteLine(">> Current Public Key <<");
        Console.WriteLine();
        Console.WriteLine("RSA XML");
        Console.WriteLine(">>>>>>>>>>>");
        Console.WriteLine(publicKey);
        Console.WriteLine(">>>>>>>>>>>");
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine("RSA PEM (1024)");
        Console.WriteLine(">>>>>>>>>>>");
        Console.WriteLine(publicRSAKeyPEM);
        Console.WriteLine(">>>>>>>>>>>");
        Console.WriteLine();
        Console.WriteLine();
        Console.WriteLine("Ethereum");
        Console.WriteLine(">>>>>>>>>>>");
        Console.WriteLine("Address: "+address);
        Console.WriteLine("Public Key: " + publicKeyEthereum);
        Console.WriteLine(">>>>>>>>>>>");


        Console.WriteLine();
        Console.WriteLine();

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}


public class Identicon
{
    /// <summary>
    /// Creates new identicon for ethereum address. Standard size of identicon is 8.
    /// </summary>
    /// <param name="Seed">Ethereum address (with 0x prefix)</param>
    /// <param name="Size">Size of the identicon (use 8 for standard identicon)</param>
    public Identicon(string Seed, int size, int scale)
    {
        Scale = scale;
        Size = size;
        createImageData(Seed);
    }


    public void SavePng(string path)
    {

        CreateEthereumIcon(Size, Scale, iconPixels).SaveAsPng(path);
    }



    private Int32[] randseed = new Int32[4];
    private Rgba32[] iconPixels;
    private int Scale;
    private int Size;

    private void seedrand(string seed)
    {
        char[] seedArray = seed.ToCharArray();
        for (int i = 0; i < randseed.Length; i++)
            randseed[i] = 0;
        for (int i = 0; i < seed.Length; i++)
            randseed[i % 4] = ((randseed[i % 4] << 5) - randseed[i % 4]) + seedArray[i];
    }

    private double rand()
    {
        var t = randseed[0] ^ (randseed[0] << 11);

        randseed[0] = randseed[1];
        randseed[1] = randseed[2];
        randseed[2] = randseed[3];
        randseed[3] = (randseed[3] ^ (randseed[3] >> 19) ^ t ^ (t >> 8));
        return Convert.ToDouble(randseed[3]) / Convert.ToDouble((UInt32)1 << 31);
    }

    private double hue2rgb(double p, double q, double t)
    {
        if (t < 0) t += 1;
        if (t > 1) t -= 1;
        if (t < 1D / 6) return p + (q - p) * 6 * t;
        if (t < 1D / 2) return q;
        if (t < 2D / 3) return p + (q - p) * (2D / 3 - t) * 6;
        return p;
    }

    private Rgba32 HSLtoRGB(double h, double s, double l)
    {
        double r, g, b;
        if (s == 0)
        {
            r = g = b = l; // achromatic
        }
        else
        {
            var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
            var p = 2 * l - q;
            r = hue2rgb(p, q, h + 1D / 3);
            g = hue2rgb(p, q, h);
            b = hue2rgb(p, q, h - 1D / 3);
        }
        return new Rgba32((byte)Math.Round(r * 255), (byte)Math.Round(g * 255), (byte)Math.Round(b * 255));
    }

    private Rgba32 createColor()
    {
        var h = (rand());
        var s = ((rand() * 0.6) + 0.4);
        var l = ((rand() + rand() + rand() + rand()) * 0.25);
        return HSLtoRGB(h, s, l);
    }

    private void createImageData(string seed)
    {
        seedrand(seed.ToLower());
        var mainColor = createColor();
        var bgColor = createColor();
        var spotColor = createColor();

        int width = Size;
        int height = Size;

        int mirrorWidth = width / 2;
        int dataWidth = width - mirrorWidth;
        double[] data = new double[width * height];
        for (int y = 0; y < height; y++)
        {
            double[] row = new double[dataWidth];
            for (int x = 0; x < dataWidth; x++)
            {
                row[x] = Math.Floor(rand() * 2.3);
            }
            Array.Copy(row, 0, data, y * width, dataWidth);
            Array.Copy(row.Reverse().ToArray(), 0, data, y * width + dataWidth, mirrorWidth);
        }

        iconPixels = new Rgba32[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == 1)
            {
                iconPixels[i] = mainColor;
            }
            else if (data[i] == 0)
            {
                iconPixels[i] = bgColor;
            }
            else
            {
                iconPixels[i] = spotColor;
            }
        }
    }

    private static Image<Rgba32> CreateEthereumIcon(int size, int scale, Rgba32[] iconPixels)
    {
        Image<Rgba32> pic = new Image<Rgba32>(size * scale, size * scale);
        for (int i = 0; i < iconPixels.Length; i++)
        {
            int x = i % size;
            int y = i / size;
            for (int xx = x * scale; xx < x * scale + scale; xx++)
            {
                for (int yy = y * scale; yy < y * scale + scale; yy++)
                {
                    pic[xx, yy] = iconPixels[i];
                }
            }
        }

        return pic;
    }
}


public class PemToXmlConverter
{


    public void Generate1024RsaKey(out string privateXmlKey, out string publicXmlKey, out string privatePem, out string publicPem)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.KeySize = 1024;
            privateXmlKey = rsa.ToXmlString(true);
            publicXmlKey = rsa.ToXmlString(false);
            privatePem = rsa.ExportRSAPrivateKeyPem();
            publicPem = rsa.ExportRSAPublicKeyPem();
        }
    }
    public void GenerateEthereumKey(out string privateKeyEthereum, out string publicKeyEthereum, out string address)
    {

        var ecKey = EthECKey.GenerateKey();
        privateKeyEthereum = ecKey.GetPrivateKeyAsBytes().ToHex();
        publicKeyEthereum = ecKey.GetPubKey().ToHex();
        address = ecKey.GetPublicAddress();
    }


    public static string ConvertPrivateKey(string pemPrivateKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(pemPrivateKey);
        RSAParameters parameters = rsa.ExportParameters(true);

        XmlDocument xmlDoc = new XmlDocument();
        XmlElement root = xmlDoc.CreateElement("RSAKeyValue");
        xmlDoc.AppendChild(root);

        XmlElement modulus = xmlDoc.CreateElement("Modulus");
        modulus.InnerText = Convert.ToBase64String(parameters.Modulus);
        root.AppendChild(modulus);

        XmlElement exponent = xmlDoc.CreateElement("Exponent");
        exponent.InnerText = Convert.ToBase64String(parameters.Exponent);
        root.AppendChild(exponent);

        XmlElement p = xmlDoc.CreateElement("P");
        p.InnerText = Convert.ToBase64String(parameters.P);
        root.AppendChild(p);

        XmlElement q = xmlDoc.CreateElement("Q");
        q.InnerText = Convert.ToBase64String(parameters.Q);
        root.AppendChild(q);

        XmlElement dp = xmlDoc.CreateElement("DP");
        dp.InnerText = Convert.ToBase64String(parameters.DP);
        root.AppendChild(dp);

        XmlElement dq = xmlDoc.CreateElement("DQ");
        dq.InnerText = Convert.ToBase64String(parameters.DQ);
        root.AppendChild(dq);

        XmlElement inverseQ = xmlDoc.CreateElement("InverseQ");
        inverseQ.InnerText = Convert.ToBase64String(parameters.InverseQ);
        root.AppendChild(inverseQ);

        XmlElement d = xmlDoc.CreateElement("D");
        d.InnerText = Convert.ToBase64String(parameters.D);
        root.AppendChild(d);

        return xmlDoc.OuterXml;
    }

    public static string ConvertPublicKey(string pemPublicKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(pemPublicKey);
        RSAParameters parameters = rsa.ExportParameters(false);

        XmlDocument xmlDoc = new XmlDocument();
        XmlElement root = xmlDoc.CreateElement("RSAKeyValue");
        xmlDoc.AppendChild(root);

        XmlElement modulus = xmlDoc.CreateElement("Modulus");
        modulus.InnerText = Convert.ToBase64String(parameters.Modulus);
        root.AppendChild(modulus);

        XmlElement exponent = xmlDoc.CreateElement("Exponent");
        exponent.InnerText = Convert.ToBase64String(parameters.Exponent);
        root.AppendChild(exponent);

        return xmlDoc.OuterXml;
    }
}