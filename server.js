/* eslint-disable no-undef */
/**
 * ============================================================================
 * MICROSERVIÇO DE TRANSMISSÃO eSOCIAL — Deploy externo (Node.js)
 * ============================================================================
 * 
 * ⚠️ ESTE ARQUIVO NÃO É IMPORTADO PELO BASE44.
 * Ele é o código-fonte do microserviço que você implanta em um servidor
 * externo (Railway, Render, VPS, etc).
 * 
 * PASSO A PASSO DE DEPLOY:
 * 
 * 1. Crie uma pasta no servidor e copie este arquivo como `server.js`
 * 
 * 2. Crie um arquivo `package.json` na mesma pasta com este conteúdo:
 *    {
 *      "name": "esocial-microservice",
 *      "version": "1.0.0",
 *      "type": "commonjs",
 *      "scripts": { "start": "node server.js" },
 *      "dependencies": {
 *        "express": "^4.19.2",
 *        "node-forge": "^1.3.1",
 *        "xml-crypto": "^6.0.1",
 *        "axios": "^1.7.2"
 *      }
 *    }
 * 
 * 3. Instale as dependências:  npm install
 * 
 * 4. Defina as variáveis de ambiente:
 *    - PORT=3000 (ou a porta do provedor)
 *    - AUTH_TOKEN=<gere um token forte e aleatório>
 * 
 * 5. Inicie o servidor:  node server.js
 * 
 * 6. No Base44, vá nas configurações do app e adicione as secrets:
 *    - MICROSERVICE_URL = https://sua-app.railway.app (sua URL pública)
 *    - MICROSERVICE_TOKEN = <o mesmo AUTH_TOKEN do passo 4>
 * 
 * 7. Pronto! O botão "Transmitir" na página eSocial do Base44 agora
 *    envia os eventos pelo seu microserviço.
 * ============================================================================
 */

const express = require('express');
const axios = require('axios');
const https = require('https');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));

const AUTH_TOKEN = process.env.AUTH_TOKEN;
const PORT = process.env.PORT || 3000;

if (!AUTH_TOKEN) {
  console.error('❌ Defina a variável AUTH_TOKEN antes de iniciar.');
  process.exit(1);
}

// ── Endpoints eSocial (S-1.0) ──
const ENDPOINTS = {
  'Produção Restrita': {
    enviar: 'https://webservices.producaorestrita.esocial.gov.br/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc',
    consultar: 'https://webservices.producaorestrita.esocial.gov.br/servicos/empregador/consultarloteeventos/WsConsultarLoteEventos.svc',
  },
  'Produção Oficial': {
    enviar: 'https://webservices.envio.esocial.gov.br/servicos/empregador/enviarloteeventos/WsEnviarLoteEventos.svc',
    consultar: 'https://webservices.envio.esocial.gov.br/servicos/empregador/consultarloteeventos/WsConsultarLoteEventos.svc',
  },
};

// ── Middleware de autenticação ──
app.use((req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (token !== AUTH_TOKEN) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  next();
});

// ── Health check ──
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Extrai chave privada e certificado do PFX ──
function parsePfx(pfxBase64, senha) {
  const pfxDer = forge.util.decode64(pfxBase64);
  const p12Asn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, senha);

  let privateKey = null;
  let certificate = null;

  const keyBags =
    p12.getBags({ bagType: forge.pki.oids.keyBag })[
      forge.pki.oids.keyBag
    ] || [];

  const shroudedKeyBags =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
      forge.pki.oids.pkcs8ShroudedKeyBag
    ] || [];

  const certBags =
    p12.getBags({ bagType: forge.pki.oids.certBag })[
      forge.pki.oids.certBag
    ] || [];

  for (const bag of keyBags) {
    if (bag.key) {
      privateKey = forge.pki.privateKeyToPem(bag.key);
      break;
    }
  }

  if (!privateKey) {
    for (const bag of shroudedKeyBags) {
      if (bag.key) {
        privateKey = forge.pki.privateKeyToPem(bag.key);
        break;
      }
    }
  }

  for (const bag of certBags) {
    if (bag.cert) {
      certificate = forge.pki.certificateToPem(bag.cert);
      break;
    }
  }

  console.log('Bags encontradas:', {
    keyBag: keyBags.length,
    shroudedKeyBag: shroudedKeyBags.length,
    certBag: certBags.length,
    keyBagTemKey: keyBags.map(b => Boolean(b.key)),
    keyBagTemAsn1: keyBags.map(b => Boolean(b.asn1)),
    shroudedTemKey: shroudedKeyBags.map(b => Boolean(b.key)),
    shroudedTemAsn1: shroudedKeyBags.map(b => Boolean(b.asn1)),
    certBagTemCert: certBags.map(b => Boolean(b.cert))
  });

  if (!privateKey || !certificate) {
    throw new Error(
      `Não foi possível extrair o PFX: ` +
      `keyBag=${keyBags.length}, ` +
      `shroudedKeyBag=${shroudedKeyBags.length}, ` +
      `certBag=${certBags.length}.`
    );
  }

  return { privateKey, certificate };
}

// ── Baixa o arquivo PFX (de uma URL) ──
async function downloadPfx(url) {
  console.log("Baixando PFX:", url);

  const response = await axios.get(url, {
    responseType: 'arraybuffer'
  });

  console.log("Status:", response.status);
  console.log("Content-Type:", response.headers["content-type"]);
  console.log("Tamanho:", response.data.length);

  return Buffer.from(response.data).toString("base64");
}

// ── Assina um evento XML com XMLDSig (enveloped, SHA-256) ──
function assinarEvento(xmlEvento, privateKey, certificate) {
  const idMatch = xmlEvento.match(/Id="([^"]+)"/);
  if (!idMatch) throw new Error('Atributo Id não encontrado no XML do evento');
  const eventId = idMatch[1];

  const sig = new SignedXml({
    privateKey,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  });

  sig.addReference({
    xpath: `//*[@Id="${eventId}"]`,
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    ],
  });

  sig.computeSignature(xmlEvento);
  return sig.getSignedXml();
}

// ── Monta o lote (batch) de eventos ──
function montarLote(xmlsAssinados, cnpj, grupo = '1') {
  const loteId = String(Date.now());
  const eventosXml = xmlsAssinados.map(xml => `        ${xml}`).join('\n');

  return `<eSocial xmlns="http://www.esocial.gov.br/schema/lote/eventos/envio/v1_1_1">
  <envioLoteEventos grupo="${grupo}">
    <ideEmpregador>
      <tpInsc>1</tpInsc>
      <nrInsc>${cnpj.slice(0, 14)}</nrInsc>
    </ideEmpregador>
    <ideTransmissor>
      <tpInsc>1</tpInsc>
      <nrInsc>${cnpj.slice(0, 14)}</nrInsc>
    </ideTransmissor>
    <eventos>
${eventosXml}
    </eventos>
  </envioLoteEventos>
</eSocial>`;
}

// ── Monta o envelope SOAP ──
function montarSoap(loteXml) {
  return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:EnviarLoteEventos xmlns:ns2="http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/v1_1_1">
      <loteEventos>
        ${loteXml}
      </loteEventos>
    </ns2:EnviarLoteEventos>
  </soap:Body>
</soap:Envelope>`;
}

// ── Extrai protocolo da resposta SOAP ──
function extrairProtocolo(soapResponse) {
  const match = soapResponse.match(/<protocoloEnvio>([^<]+)<\/protocoloEnvio>/);
  return match ? match[1] : null;
}

function extrairErros(soapResponse) {
  const erros = [];
  const regex = /<descricao>([^<]+)<\/descricao>/g;
  let m;
  while ((m = regex.exec(soapResponse)) !== null) {
    erros.push(m[1]);
  }
  if (erros.length === 0) {
    const codMatch = soapResponse.match(/<codigo>(\d+)<\/codigo>[\s\S]*?<descricao>([^<]+)<\/descricao>/);
    if (codMatch) erros.push(`${codMatch[1]}: ${codMatch[2]}`);
  }
  return erros;
}

// ══ ENDPOINT PRINCIPAL: Transmitir lote ══
app.post('/transmitir', async (req, res) => {
  try {
    const { eventos_xml, certificado_url, certificado_senha, ambiente, cnpj } = req.body;

    if (!eventos_xml || !Array.isArray(eventos_xml) || eventos_xml.length === 0) {
      return res.status(400).json({ error: 'eventos_xml (array) é obrigatório' });
    }
    if (!certificado_url || !certificado_senha) {
      return res.status(400).json({ error: 'certificado_url e certificado_senha são obrigatórios' });
    }
    if (!ambiente || !ENDPOINTS[ambiente]) {
      return res.status(400).json({ error: 'ambiente inválido. Use: Produção Restrita ou Produção Oficial' });
    }

    console.log(`[${new Date().toISOString()}] Transmissão: ${eventos_xml.length} evento(s), ambiente=${ambiente}`);

    // 1. Baixa e parseia o certificado
    const pfxBase64 = await downloadPfx(certificado_url);
    const { privateKey, certificate } = parsePfx(pfxBase64, certificado_senha);

    // 2. Assina cada evento
    const xmlsAssinados = eventos_xml.map((xml, i) => {
      try {
        return assinarEvento(xml, privateKey, certificate);
      } catch (err) {
        throw new Error(`Erro ao assinar evento ${i + 1}: ${err.message}`);
      }
    });

    // 3. Monta o lote e o envelope SOAP
    const loteXml = montarLote(xmlsAssinados, cnpj);
    const soapEnvelope = montarSoap(loteXml);

    // 4. Configura o agente HTTPS com mTLS
    const httpsAgent = new https.Agent({
      pfx: Buffer.from(pfxBase64, 'base64'),
      passphrase: certificado_senha,
      rejectUnauthorized: true,
    });

    const endpoint = ENDPOINTS[ambiente].enviar;
    console.log(`[${new Date().toISOString()}] Enviando para ${endpoint}`);

    // 5. Envia a requisição SOAP
    const response = await axios.post(endpoint, soapEnvelope, {
      httpsAgent,
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'http://www.esocial.gov.br/servicos/empregador/lote/eventos/envio/v1_1_1/IWSEnviarLoteEventos/EnviarLoteEventos',
      },
      timeout: 60000,
    });

    const soapResponse = response.data;
    console.log(`[${new Date().toISOString()}] Resposta recebida`);

    // 6. Processa a resposta
    const protocolo = extrairProtocolo(soapResponse);
    const erros = extrairErros(soapResponse);

    if (protocolo) {
      res.json({
        success: true,
        protocolo,
        mensagem: `Lote transmitido com sucesso. Protocolo: ${protocolo}`,
        resposta_raw: soapResponse.substring(0, 5000),
      });
    } else if (erros.length > 0) {
      res.json({
        success: false,
        protocolo: null,
        mensagem: `Erros na transmissão: ${erros.join('; ')}`,
        erros,
        resposta_raw: soapResponse.substring(0, 5000),
      });
    } else {
      res.json({
        success: true,
        protocolo: null,
        mensagem: 'Lote enviado. Resposta sem protocolo explícito — verifique a consulta.',
        resposta_raw: soapResponse.substring(0, 5000),
      });
    }

  } catch (error) {
    console.error(`[${new Date().toISOString()}] ERRO:`, error.message);
    const statusCode = error.response?.status || 500;
    const errorData = error.response?.data || error.message;
    res.status(statusCode).json({
      error: error.message,
      detalhe: typeof errorData === 'string' ? errorData.substring(0, 2000) : errorData,
    });
  }
});

// ══ ENDPOINT: Consultar lote ══
app.post('/consultar', async (req, res) => {
  try {
    const { protocolo, certificado_url, certificado_senha, ambiente } = req.body;

    if (!protocolo) return res.status(400).json({ error: 'protocolo é obrigatório' });
    if (!certificado_url || !certificado_senha) return res.status(400).json({ error: 'certificado_url e certificado_senha são obrigatórios' });

    const pfxBase64 = await downloadPfx(certificado_url);
    const httpsAgent = new https.Agent({
      pfx: Buffer.from(pfxBase64, 'base64'),
      passphrase: certificado_senha,
      rejectUnauthorized: true,
    });

    const soapEnvelope = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns2:ConsultarLoteEventos xmlns:ns2="http://www.esocial.gov.br/servicos/empregador/lote/eventos/consulta/v1_1_1">
      <consultarLoteEventos>
        <protocoloEnvio>${protocolo}</protocoloEnvio>
      </consultarLoteEventos>
    </ns2:ConsultarLoteEventos>
  </soap:Body>
</soap:Envelope>`;

    const endpoint = ENDPOINTS[ambiente]?.consultar || ENDPOINTS['Produção Restrita'].consultar;

    const response = await axios.post(endpoint, soapEnvelope, {
      httpsAgent,
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'http://www.esocial.gov.br/servicos/empregador/lote/eventos/consulta/v1_1_1/IWSConsultarLoteEventos/ConsultarLoteEventos',
      },
      timeout: 60000,
    });

    res.json({
      success: true,
      resposta_raw: response.data.substring(0, 10000),
    });

  } catch (error) {
    console.error('Erro na consulta:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ══ ENDPOINT: Testar certificado ══
app.post('/testar-certificado', async (req, res) => {
  try {
    const { certificado_url, certificado_senha } = req.body;
    const pfxBase64 = await downloadPfx(certificado_url);
    const { privateKey, certificate } = parsePfx(pfxBase64, certificado_senha);

    const certObj = forge.pki.certificateFromPem(certificate);
    const validade = certObj.validity.notAfter;

    res.json({
      success: true,
      mensagem: 'Certificado válido e acessível.',
      emissor: certObj.issuer?.attributes?.map(a => a.value).join(', ') || '—',
      validade: validade.toISOString(),
    });
  } catch (error) {
    res.status(400).json({ error: `Certificado inválido: ${error.message}` });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Microserviço eSocial rodando na porta ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
});
