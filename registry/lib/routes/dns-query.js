import * as base64url from 'base64url'
import * as dnsPacket from 'dns-packet'

const dnsQuery = async question => {
  if (question.class == 'IN' && question.type == 'A') {
    const hcid = question.name.toLowerCase().split('.').slice(-3)[0]

    const ipv4 = await AGENT_ID_TO_IPV4.get(hcid)

    if (ipv4 != null) {
      return [{
        class: 'IN',
        data: ipv4,
        name: question.name,
        ttl: 10, // 10 seconds
        type: 'A'
      }]
    }
  }
}

const handle = async req => {
  const url = new URL(req.url)
  const reqBuffer = base64url.toBuffer(url.searchParams.get('dns'))
  const reqPacket = dnsPacket.decode(reqBuffer)

  if (reqPacket.questions.length != 1) {
    return new Response(null, { status: 400 })
  }

  const resPacket = {
    type: 'response',
    id: reqPacket.id,
    questions: reqPacket.questions,
    answers: await dnsQuery(reqPacket.questions[0]) || []
  }

  return new Response(dnsPacket.encode(resPacket), {
    headers: { 'content-type': 'application/dns-message' }
  })
}

export { handle }
