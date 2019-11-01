import * as dnsPacket from 'dns-packet'

const dnsQuery = async question => {
  if (question.class == 'IN' && question.type == 'A') {
    const [hcid, domain, tld] = question.name.split('.').slice(-3)

    if (domain == 'holohost' && tld == 'net') {
      const ipv4 = await AGENT_ID_TO_IPV4.get(hcid)

      if (ipv4 != null) {
        return [{
          class: 'IN',
          data: ipv4,
          name: question.name,
          ttl: 300, // 5 minutes
          type: 'A'
        }]
      }
    }
  }
}

const handle = async req => {
  const reqBuffer = Buffer.from(await req.arrayBuffer())
  const reqPacket = dnsPacket.decode(reqBuffer)

  if (reqPacket.questions.length != 1) {
    return new Response(null, { status: 400 })
  }

  const resPacket = {
    type: 'response',
    questions: reqPacket.questions,
    answers: await dnsQuery(reqPacket.questions[0]) || []
  }

  return new Response(dnsPacket.encode(resPacket), {
    headers: { 'content-type': 'application/dns-message' }
  })
}

export { handle }