#!/usr/bin/env php
<?php
/**
 * crypto_demo.php
 * Requisitos: PHP 8+ com extensão OpenSSL ativa.
 *
 * Subcomandos:
 *  - gen-keys <outdir> [passphrase]
 *  - sym:enc "<texto>" "<senha>"
 *  - sym:dec '<json>'
 *  - hybrid:enc "<texto>" <public.pem>
 *  - hybrid:dec '<json>' <private.pem> [passphrase]
 */

ini_set('display_errors', 'stderr');
error_reporting(E_ALL);

function fail($msg, $code = 1) {
    fwrite(STDERR, "[erro] $msg\n");
    exit($code);
}

function b64e(string $bin): string { return base64_encode($bin); }
function b64d(string $b64): string { return base64_decode($b64, true) ?? fail("Base64 inválido"); }

function jsonOut($arr) {
    $json = json_encode($arr, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    if ($json === false) fail("Falha ao gerar JSON");
    echo $json . PHP_EOL;
}

/** --------- SIMÉTRICO (AES-256-GCM + PBKDF2) --------- */
function symEncrypt(string $plaintext, string $password): array {
    $cipher = 'aes-256-gcm';
    if (!in_array($cipher, openssl_get_cipher_methods(true))) {
        fail("Cipher $cipher não suportado pelo OpenSSL desta máquina.");
    }

    $salt = random_bytes(16);                 // para PBKDF2
    $iv   = random_bytes(12);                 // 12 bytes é o recomendado para GCM
    $iter = 200000;                           // ~200k iterações
    $key  = hash_pbkdf2('sha256', $password, $salt, $iter, 32, true);

    $tag = '';
    $ct = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '');
    if ($ct === false) fail('Falha em openssl_encrypt (simétrico).');

    return [
        'type'       => 'sym',
        'alg'        => 'AES-256-GCM',
        'kdf'        => 'PBKDF2-HMAC-SHA256',
        'iterations' => $iter,
        'salt'       => b64e($salt),
        'iv'         => b64e($iv),
        'tag'        => b64e($tag),
        'ct'         => b64e($ct),
    ];
}

function symDecrypt(array $pkg, string $password): string {
    foreach (['salt','iv','tag','ct','iterations'] as $f) {
        if (!isset($pkg[$f])) fail("Pacote simétrico inválido: falta '$f'.");
    }
    $cipher = 'aes-256-gcm';
    $salt = b64d($pkg['salt']);
    $iv   = b64d($pkg['iv']);
    $tag  = b64d($pkg['tag']);
    $ct   = b64d($pkg['ct']);
    $iter = (int)$pkg['iterations'];

    $key = hash_pbkdf2('sha256', $password, $salt, $iter, 32, true);

    $pt = openssl_decrypt($ct, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '');
    if ($pt === false) fail('Falha em openssl_decrypt (simétrico). A senha pode estar incorreta ou o pacote foi alterado.');
    return $pt;
}

/** --------- ASSIMÉTRICO (RSA-OAEP) + HÍBRIDO --------- */
function hybridEncrypt(string $plaintext, string $publicPem): array {
    $pubKey = openssl_pkey_get_public($publicPem);
    if ($pubKey === false) fail('Chave pública inválida.');

    // chave de sessão AES
    $symKey = random_bytes(32);
    $iv     = random_bytes(12);

    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $symKey, OPENSSL_RAW_DATA, $iv, $tag, '');
    if ($ct === false) fail('Falha em openssl_encrypt (híbrido).');

    // Criptografa a chave simétrica com RSA-OAEP
    $ek = '';
    if (!openssl_public_encrypt($symKey, $ek, $pubKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        fail('Falha em openssl_public_encrypt (RSA-OAEP).');
    }

    return [
        'type' => 'hybrid',
        'alg'  => 'RSA-OAEP + AES-256-GCM',
        'ek'   => b64e($ek),
        'iv'   => b64e($iv),
        'tag'  => b64e($tag),
        'ct'   => b64e($ct),
    ];
}

function hybridDecrypt(array $pkg, string $privatePem, ?string $passphrase): string {
    foreach (['ek','iv','tag','ct'] as $f) {
        if (!isset($pkg[$f])) fail("Pacote híbrido inválido: falta '$f'.");
    }
    $privKey = openssl_pkey_get_private($privatePem, $passphrase ?? '');
    if ($privKey === false) fail('Chave privada inválida ou passphrase incorreta.');

    $ek  = b64d($pkg['ek']);
    $iv  = b64d($pkg['iv']);
    $tag = b64d($pkg['tag']);
    $ct  = b64d($pkg['ct']);

    $symKey = '';
    if (!openssl_private_decrypt($ek, $symKey, $privKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        fail('Falha em openssl_private_decrypt (RSA-OAEP).');
    }

    $pt = openssl_decrypt($ct, 'aes-256-gcm', $symKey, OPENSSL_RAW_DATA, $iv, $tag, '');
    if ($pt === false) fail('Falha em openssl_decrypt (híbrido). Pacote pode estar corrompido.');
    return $pt;
}

/** --------- GERAÇÃO DE CHAVES RSA --------- */
function genRsaKeys(string $outDir, ?string $passphrase) {
    if (!is_dir($outDir) && !mkdir($outDir, 0700, true)) {
        fail("Não foi possível criar diretório: $outDir");
    }

    // 🔧 Windows precisa, muitas vezes, do caminho explícito do openssl.cnf
    $cfg = [
        'private_key_bits' => 4096,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    if (stripos(PHP_OS_FAMILY, 'Windows') === 0) {
        // use o caminho que você tem aí
        $cnf = 'C:\\php\\extras\\ssl\\openssl.cnf';
        if (file_exists($cnf)) {
            $cfg['config'] = $cnf;
            // reforça por variável também, caso a lib use
            putenv("OPENSSL_CONF={$cnf}");
        }
    }

    $res = openssl_pkey_new($cfg);
    if ($res === false) {
        $errs = [];
        while ($e = openssl_error_string()) { $errs[] = $e; }
        fail('Falha ao gerar par de chaves RSA: ' . ($errs ? implode(' | ', $errs) : 'sem detalhes (tente com 2048 bits ou verifique o config)'));
    }

    $privPem = '';
    if (!openssl_pkey_export($res, $privPem, $passphrase ?? null, $cfg)) {
        $errs = [];
        while ($e = openssl_error_string()) { $errs[] = $e; }
        fail('Falha ao exportar chave privada: ' . implode(' | ', $errs));
    }

    $pubDetails = openssl_pkey_get_details($res);
    if ($pubDetails === false || empty($pubDetails['key'])) fail('Falha ao obter chave pública.');
    $pubPem = $pubDetails['key'];

    $privPath = rtrim($outDir, '/\\') . DIRECTORY_SEPARATOR . 'private.pem';
    $pubPath  = rtrim($outDir, '/\\') . DIRECTORY_SEPARATOR . 'public.pem';

    if (file_put_contents($privPath, $privPem) === false) fail("Falha ao salvar $privPath");
    if (file_put_contents($pubPath,  $pubPem) === false) fail("Falha ao salvar $pubPath");

    @chmod($privPath, 0600);
    @chmod($pubPath, 0644);

    fwrite(STDERR, "Chaves salvas em:\n  - $privPath\n  - $pubPath\n");
}

function readJsonArg(string $argOrPath): array {
    // Se for arquivo, lê; senão usa o texto recebido
    $json = is_file($argOrPath)
        ? (file_get_contents($argOrPath) ?: fail("Não foi possível ler $argOrPath"))
        : $argOrPath;

    // Remove BOM UTF-8
    if (substr($json, 0, 3) === "\xEF\xBB\xBF") $json = substr($json, 3);

    // Converte UTF-16/32/Latin-1 -> UTF-8 se necessário (problema típico do PowerShell)
    $enc = mb_detect_encoding($json, ['UTF-8','UTF-16LE','UTF-16BE','UTF-32LE','UTF-32BE','Windows-1252','ISO-8859-1'], true);
    if ($enc && $enc !== 'UTF-8') $json = mb_convert_encoding($json, 'UTF-8', $enc);

    $pkg = json_decode($json, true);
    if (!is_array($pkg)) {
        $msg = function_exists('json_last_error_msg') ? json_last_error_msg() : 'JSON inválido';
        fail("JSON inválido: $msg");
    }
    return $pkg;
}

function usage() {
    echo <<<TXT
Uso:
  php crypto_demo.php gen-keys <outdir> [passphrase]
  php crypto_demo.php sym:enc "<texto>" "<senha>" | Out-File -Encoding utf8 -NoNewline .\sym_pkg.json
  php crypto_demo.php sym:dec '<json>'
  php crypto_demo.php hybrid:enc "<texto>" <public.pem> | Out-File -Encoding utf8 -NoNewline .\hybrid_pkg.json
  php crypto_demo.php hybrid:dec '<json>' <private.pem> [passphrase]

Dicas:
- Para evitar problemas de aspas, salve o JSON de saída em arquivo e use esse arquivo depois.
- O modo simétrico usa AES-256-GCM com PBKDF2 (200k iterações), sal e IV aleatórios.
- O modo híbrido usa AES-256-GCM para dados e RSA-OAEP para proteger a chave simétrica.

TXT;
}

$cmd = $argv[1] ?? null;
if (!$cmd) { usage(); exit(0); }

try {
    switch ($cmd) {
        case 'gen-keys': {
            $outDir = $argv[2] ?? fail('Informe <outdir>.');
            $pass   = $argv[3] ?? null;
            genRsaKeys($outDir, $pass);
            break;
        }
        case 'sym:enc': {
            $text = $argv[2] ?? fail('Informe "<texto>".');
            $pass = $argv[3] ?? fail('Informe "<senha>".');
            $pkg = symEncrypt($text, $pass);
            jsonOut($pkg);
            break;
        }
        case 'sym:dec': {
            $arg = $argv[2] ?? fail("Informe '<json>' ou <arquivo.json>.");
            $pkg = readJsonArg($arg);
            $pass = readline("Senha: ");
            echo symDecrypt($pkg, $pass) . PHP_EOL;
            break;
        }
        case 'hybrid:enc': {
            $text = $argv[2] ?? fail('Informe "<texto>".');
            $pubPath = $argv[3] ?? fail('Informe <public.pem>.');
            $publicPem = @file_get_contents($pubPath);
            if ($publicPem === false) fail("Não foi possível ler $pubPath");
            $pkg = hybridEncrypt($text, $publicPem);
            jsonOut($pkg);
            break;
        }
        case 'hybrid:dec': {
            $arg      = $argv[2] ?? fail("Informe '<json>' ou <arquivo.json>.");
            $privPath = $argv[3] ?? fail('Informe <private.pem>.');
            $pass     = $argv[4] ?? null;

            $pkg = readJsonArg($arg);

            $privatePem = @file_get_contents($privPath);
            if ($privatePem === false) fail("Não foi possível ler $privPath");

            echo hybridDecrypt($pkg, $privatePem, $pass) . PHP_EOL;
            break;
        }
        default:
            usage();
    }
} catch (Throwable $e) {
    fail($e->getMessage());
}
