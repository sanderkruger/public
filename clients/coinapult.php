<?php

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Serializer\Signature\HexSignatureSerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;

class Coinapult
{
  const DEBUG = FALSE;

  /* Valid keys while searching for transactions. */
  private static $SEARCH_CRITERIA = array('transaction_id', 'type',
    'currency', 'to', 'from', 'extOID', 'txhash');
  private static $COINAPULTPUB_PEM = "-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWp9wd4EuLhIZNaoUgZxQztSjrbqgTT0w
LBq8RwigNE6nOOXFEoGCjGfekugjrHWHUi8ms7bcfrowpaJKqMfZXg==
-----END PUBLIC KEY-----
";

  private $_base_url = 'https://api.coinapult.com/api/';

  private $_api_key = null;
  private $_api_secret = null;

  // ECC properties
  private $ecc = false;
  private $pubkey = null;
  private $privkey = null;

  public function __construct($ecc, $api_key, $api_secret, $base_url=NULL)
  {
    $this->ecc = $ecc;
    if ($ecc) {
      $this->pubkey = $api_key;
      $this->privkey = $api_secret;
    } else {
      $this->_api_key = $api_key;
      $this->_api_secret = $api_secret;
    }
    if (!is_null($base_url)) {
      $this->_base_url = $base_url;
    }
  }

  /* Auxiliary functions for sending signed requests to Coinapult. */
  private function prepareECC($params) {
    /* Define the headers and parameters required for sending
     * a ECC signed request to Coinapult.
     */
    $headers = array();

    if (isset($params['newAccount'])) {
      /* Do not set a nonce when creating new account. */
      $headers[] = 'cpt-ecc-new: ' . base64_encode($this->pubkey->pem);
      unset($params['newAccount']);
    } else {
      $headers[] = 'cpt-ecc-pub: ' . $this->pubkey->hash;
      $params['nonce'] = gen_nonce();
    }
    $params['timestamp'] = time();

    $data = base64_encode(json_encode($params));
    $adapter = EccFactory::getAdapter();
    $generator = EccFactory::getNistCurves()->generator384();
    $useDerandomizedSignatures = true;
    $algorithm = 'sha256';

    $signer = new Signer($adapter);
    $hash = $signer->hashData($generator, $algorithm, $data);

    if ($useDerandomizedSignatures) {
      $random = \Mdanter\Ecc\Random\RandomGeneratorFactory::getHmacRandomGenerator($this->privkey->key, $hash, $algorithm);
    } else {
      $random = \Mdanter\Ecc\Random\RandomGeneratorFactory::getRandomGenerator();
    }

    $randomK = $random->generate($generator->getOrder());
    $signature = $signer->sign($this->privkey->key, $hash, $randomK);
    $serializer = new HexSignatureSerializer();
    $serializedSig = $serializer->serialize($signature);
    $headers[] = 'cpt-ecc-sign: ' . $serializedSig;
    
    return array($headers, $data);
  }

  private function receiveECC($content) {
    $adapter = EccFactory::getAdapter();
    $generator = EccFactory::getNistCurves()->generator384();
    $algorithm = 'sha256';

    // Parse signature
    $sigSerializer = new HexSignatureSerializer();
    $sig = $sigSerializer->parse($content->sign);

    // Parse public key
    $derSerializer = new DerPublicKeySerializer($adapter);
    $pemSerializer = new PemPublicKeySerializer($derSerializer);
    $key = $pemSerializer->parse(self::$COINAPULTPUB_PEM);

    $signer = new Signer($adapter);
    $hash = $signer->hashData($generator, $algorithm, $content->data);
    $check = $signer->verify($key, $sig, $hash);
    if ($check) {
      $obj = json_decode($content->data);
      $obj->validSign = true;
    } else {
      $obj = new stdClass();
      $obj->validSign = false;
    }
    return $obj;
  }

  /* Make a call to the Coinapult API. */
  private function request($method, $params, $sign=TRUE, $post=TRUE) {
    $headers = array();
    if ($sign) {
      if ($this->ecc) {
        $result = $this->prepareECC($params);
        $headers = $result[0];
        $data = array("data" => $result[1]);
      } else {
        $params['nonce'] = gen_nonce();
        $params['timestamp'] = (string)time();
        $params['endpoint'] = '/' . $method;
        $headers[] = 'cpt-key: ' . $this->_api_key;
        $signdata = base64_encode(json_encode($params));
        $headers[] = 'cpt-hmac: ' . hash_hmac("sha512", $signdata, $this->_api_secret);
        $data = array("data" => $signdata);
      }
      $params_str = http_build_query($data, '', '&');
    } else {
      $params_str = http_build_query($params, '', '&');
    }

    $handle = curl_init();
    if (Coinapult::DEBUG) {
      curl_setopt($handle, CURLOPT_VERBOSE, TRUE);
    }
    curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($handle, CURLOPT_URL, $this->_base_url . $method);
    curl_setopt($handle, CURLOPT_POSTFIELDS, $params_str);
    curl_setopt($handle, CURLOPT_POST, $post);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, TRUE);
    $result = curl_exec($handle);
    if (curl_errno($handle)) {
      throw new Exception(curl_error($handle));
    }
    curl_close($handle);

    $data = json_decode($result);
    return $data;
  }

  /* Coinapult API. */

  public function ticker($begin=NULL, $end=NULL) {
    $params = array();
    if (!is_null($begin)) {
      $params['begin'] = $begin;
    }
    if (!is_null($end)) {
      $params['end'] = $end;
    }

    return $this->request('ticker', $params, $sign=FALSE, $post=FALSE);
  }

  public function account_info() {
    return $this->request('accountInfo', array());
  }

  public function get_bitcoin_address() {
    return $this->request('getBitcoinAddress', array());
  }

  public function send($amount, $address, $currency='BTC', $extOID=NULL, $callback=NULL) {
    $params = array(
      'amount'   => $amount,
      'address'  => $address,
      'currency' => $currency
    );
    if (!is_null($callback)) {
      $params['callback'] = $callback;
    }
    if (!is_null($extOID)) {
      $params['extOID'] = $extOID;
    }
    return $this->request('t/send', $params);
  }

  public function receive($amount, $inCurrency='BTC', $outAmount=NULL,
    $outCurrency=NULL, $extOID=NULL, $callback=NULL, $address=NULL) {

      $params = array();
      if (!is_null($amount)) {
        $params['amount'] = $amount;
      }

      if (is_null($inCurrency)) {
        $params['currency'] = 'BTC';
      } else {
        $params['currency'] = $inCurrency;
      }

      if (!is_null($outAmount)) {
        $params['outAmount'] = "$outAmount";
      }
      if (!is_null($outCurrency)) {
        $params['outCurrency'] = $outCurrency;
      }
      if (!is_null($extOID)) {
        $params['extOID'] = "$extOID";
      }
      if (!is_null($callback)) {
        $params['callback'] = "$callback";
      }
      if (!is_null($address)) {
        $params['address'] = "$address";
      }

      return $this->request('t/receive', $params);
    }

  public function search($criteria, $many=false, $page=NULL) {

    $params = array();
    foreach ($criteria as $key => $val) {
      if (in_array($key, Coinapult::$SEARCH_CRITERIA)) {
        $params[$key] = $val;
      } else {
        throw new Exception("Invalid search criteria '$key'");
      }
    }

    if (!count($params)) {
      throw new Exception("Empty search criteria");
    }

    if ($many) {
      $params['many'] = '1';
    }
    if (!is_null($page)) {
      $params['page'] = $page;
    }

    return $this->request('t/search', $params);
  }

  public function convert($amount, $inCurrency='BTC', $outCurrency=NULL, $callback=NULL) {

    $params = array(
      'amount'	 => $amount,
      'inCurrency' => $inCurrency
    );
    if (!is_null($outCurrency)) {
      $params['outCurrency'] = $outCurrency;
    }
    if (!is_null($callback)) {
      $params['callback'] = $callback;
    }

    return $this->request('t/convert', $params);
  }


  /* Helpers. */
  public function authenticate_callback($recv_key, $recv_hmac, $recv_data) {
    $res = array();
    $res['auth'] = FALSE;
    $res['hmac'] = '';
    if (!(strcmp($recv_key, $this->_api_key))) {
      /* API key matches. */
      $res['hmac'] = hash_hmac("sha512", $recv_data, $this->_api_secret);
      if (!(strcasecmp($res['hmac'], $recv_hmac))) {
        /* Received HMAC matches. */
        $res['auth'] = TRUE;
      }
    }
    return $res;
  }

  public function create_account() {
    $params = array('newAccount' => true);
    $data = $this->request('account/create', $params, true, true);
     if (isset($data->error)) {
      return 'Error';
    } else {
      $rdata = $this->receiveECC($data);
      if ($rdata->validSign && isset($rdata->success) && $rdata->success == $this->pubkey->hash) {
        return 'Success';
      }
    }
    return 'Error';
  }

} /* Coinapult class. */


/* Auxiliary function for sending signed requests to Coinapult. */
function gen_nonce($length=22) {
  $b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  $nonce = '';
  for ($i = 0; $i < $length; $i++) {
    $char = $b58[mt_rand(0, 57)];
    $nonce = $nonce . $char;
  }
  return $nonce;
}


?>
