
package pkcs11


// These tests depend on Eracom software HSM emulation library being in
// in /opt/eracom-5.2.0/lib/libcryptoki.so

import (
//	"fmt"
	"log"
//	"math/big"
	"os"
	"testing"
	"crypto/x509"
	//certigo "github.com/square/certigo/lib"
	//"math/big"
	//"github.com/grantae/certinfo"
	//"fmt"
	"crypto/rsa"
	"math/big"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"bytes"
)

/*
This test supports the following environment variables:

* HSM_LIB: complete path to libcryptoki.so
* HSM_TOKENLABEL
* HSM_PRIVKEYLABEL
* HSM_PIN
*/

func setenv(t *testing.T) *Ctx {
	os.Setenv("ET_PTKC_SW_DATAPATH", "/home/pm/cryptoki/cryptoki64")
	lib := "/opt/eracom-5.2.0/lib/linux-x86_64/libctsw.so"
	t.Logf("loading %s", lib)
	p := New(lib)
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func TestSetenv(t *testing.T) {
	//wd, _ := os.Getwd()
	os.Setenv("ET_PTKC_SW_DATAPATH", "/home/pm/cryptoki/cryptoki64")
	lib := "/opt/eracom-5.2.0/lib/linux-x86_64/libctsw.so"

	p := New(lib)
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	p.Destroy()
	return
}

func getSession(p *Ctx, t *testing.T) SessionHandle {
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e)
	}
	session, e := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e)
	}
	if e := p.Login(session, CKU_USER, "qwerty"); e != nil {
		t.Fatalf("user pin %s\n", e)
	}
	return session
}

func TestInitialize(t *testing.T) {
	p := setenv(t)
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	p.Finalize()
	p.Destroy()
}

func TestNew(t *testing.T) {
	if p := New(""); p != nil {
		t.Fatalf("init should have failed, got %s\n", p)
	}
	if p := New("/does/not/exist"); p != nil {
		t.Fatalf("init should have failed, got %s\n", p)
	}
}

func finishSession(p *Ctx, session SessionHandle) {
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
	p.Destroy()
}

func TestGetInfo(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("non zero error %s\n", err)
	}

	t.Logf("%+v\n", info)
}

func TestFindObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel:= "OWOC"

	template := []*Attribute{NewAttribute(CKA_LABEL, tokenLabel)}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	objs, b, e := p.FindObjects(session, 2)

	if e != nil {
		t.Fatalf("failed to find: %s %v\n", e, b)
	}

	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}

	if len(objs) != 2 {
		t.Fatal("should have found two objects")
	}
}


func savePEMKey(fileName string, key *rsa.PrivateKey) {

	outFile, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}

	var privateKey = &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key)}

	pem.Encode(outFile, privateKey)

	outFile.Close()
}



func findCertificateByModulusExp(p *Ctx, session SessionHandle, modulus *[]byte, exponent *[]byte) {

	template := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_CERTIFICATE)}

	privModulus := new(big.Int)
	privModulus.SetBytes(*modulus)

	if e := p.FindObjectsInit(session, template); e != nil {
		log.Fatalf("failed to init: %s\n", e)
	}

	objs, b, e := p.FindObjects(session, CK_MAXOBJ)
	if e != nil {
		log.Fatalf("failed to find: %s %v\n", e, b)
	}

	if e := p.FindObjectsFinal(session); e != nil {
		log.Fatalf("failed to finalize: %s\n", e)
	}

	for _, obj := range objs {

		templateCrt := []*Attribute{
			NewAttribute(CKA_LABEL, nil),
			NewAttribute(CKA_VALUE, nil),
			NewAttribute(CKA_ID, nil)}

		attr, err := p.GetAttributeValue(session, ObjectHandle(obj), templateCrt)
		if err != nil {
			log.Fatalf("err %s\n", err)
		}
		log.Printf("Certificate [%s]:", attr[0].Value)

		certs, err := x509.ParseCertificates(attr[1].Value)
		if err != nil {
			//log.Printf("Certificate [%s] fail - %s", attr[0].Value, err)
			continue
		}

/*
		if len(certs) != 1 {
			log.Fatalf("Wrong number of certs: got %d want 1", len(certs))
			return
		}
*/
		// Print the certificate
	/*
		result, err := certinfo.CertificateText(certs[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(result)
 */
		rsaPublicKey := certs[0].PublicKey.(*rsa.PublicKey)

		eReader := bytes.NewReader(*exponent)
		var e int
		err = binary.Read(eReader, binary.LittleEndian, &e)

		bb := new(big.Int).SetBytes(*exponent).Int64()

		rsaPK := rsa.PublicKey{new(big.Int).SetBytes(*modulus), int(new(big.Int).SetBytes(*exponent).Int64())}
		// && rsaPublicKey.E == rsaPK.E
		if rsaPublicKey.N.Cmp(rsaPK.N) == 0 && rsaPublicKey.E == rsaPK.E {

			log.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!  %d   %v  %d  %d", rsaPublicKey.E, *exponent, bb, e)
		}

//		exp := int(binary.LittleEndian.Uint(exponent))
//		log.Printf("exp = %d", exp)

/*
		if rsaPublicKey.N.Cmp(privModulus) == 0 && rsaPublicKey.E == exp {
			log.Print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		}
*/
		//fmt.Println(rsaPublicKey.N) /* Modulus  */
		//fmt.Println(rsaPublicKey.E) /* Exponent */

	}
}

func findCertificate(p *Ctx, session SessionHandle, o ObjectHandle, t *testing.T) {

	template_pk := []*Attribute{
		NewAttribute(CKA_LABEL, nil),
		NewAttribute(CKA_MODULUS, nil),
		NewAttribute(CKA_PUBLIC_EXPONENT, nil)}

	attr, err := p.GetAttributeValue(session, ObjectHandle(o), template_pk)
	if err != nil {
		t.Fatalf("err %s\n", err)
	}

	log.Printf("pivate key %s", attr[0].Value)
	//log.Printf("modulus %v", attr[1])
	//log.Printf("exp %v", attr[2])


	if "OWOC" == string(attr[0].Value) {
		findCertificateByModulusExp(p, session, &attr[1].Value, &attr[2].Value)
	}


/*

	template_crt := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_CERTIFICATE),
		NewAttribute(CKA_LABEL, attr[0].Value),
		//NewAttribute(CKA_MODULUS, attr[1].Value),
		NewAttribute(CKA_PUBLIC_EXPONENT, attr[2].Value)}

	if e := p.FindObjectsInit(session, template_crt); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}

	objs_crt, b, e := p.FindObjects(session, CK_MAXOBJ)
	if e != nil {
		t.Fatalf("failed to find: %s %v\n", e, b)
	}

	log.Printf("Found cert len = %d", len(objs_crt))

	if len(objs_crt) != 1 {
		t.Fatal("should have found only one object")
	}

	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}
*/
}

func TestFindPrivateKeyByCertificate(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	template := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA)}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	objs, b, e := p.FindObjects(session, CK_MAXOBJ)
	if e != nil {
		t.Fatalf("failed to find: %s %v\n", e, b)
	}

	//template_pk := []*Attribute{NewAttribute(CKA_LABEL, nil)}

	log.Printf("len = %d", len(objs))

	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}

	for _,obj := range objs {

		findCertificate(p,session,ObjectHandle(obj),t)
		/*
				attr, err := p.GetAttributeValue(session, ObjectHandle(obj), template_pk)

				if err != nil {
					t.Fatalf("err %s\n", err)
				}

				//t.Logf("%d) pivate key %s", i, attr[0].Value)
				log.Printf("%d) pivate key %s", 1, attr[0].Value)
		*/
	}


	if len(objs) != 4 {
		t.Fatal("should have found two objects")
	}
}
