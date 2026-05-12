from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import dns.resolver
import httpx
from typing import List, Optional
from datetime import datetime

app = FastAPI(
    title="MailGuard API",
    description="Professional email validation with DNS checks, disposable detection, MX verification, and bulk validation.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Large list of known disposable/temporary email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de", "guerrillamail.net",
    "guerrillamail.org", "spam4.me", "trashmail.com", "trashmail.me",
    "trashmail.net", "dispostable.com", "mailnull.com", "spamgourmet.com",
    "spamgourmet.net", "spamgourmet.org", "trashmail.at", "trashmail.io",
    "trashmail.xyz", "tempinbox.com", "fakeinbox.com", "mailnesia.com",
    "maildrop.cc", "spamfree24.org", "bccto.me", "chacuo.net", "discard.email",
    "discardmail.com", "discardmail.de", "spamspot.com", "spamthisplease.com",
    "tempail.com", "tempr.email", "discard.email", "spamgob.com", "ezztt.com",
    "filzmail.com", "gowikibooks.com", "gowikicampus.com", "gowikicars.com",
    "gowikifilms.com", "gowikigames.com", "gowikimusic.com", "gowikinetwork.com",
    "gowikitravel.com", "gowikitv.com", "spam.la", "spamfree.eu", "spamgob.com",
    "0-mail.com", "0815.ru", "0clickemail.com", "0wnd.net", "0wnd.org",
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "33mail.com",
    "anonymbox.com", "antichef.com", "antichef.net", "antireg.ru", "antispam.de",
    "casualdx.com", "cubiclink.com", "dacoolest.com", "dandikmail.com",
    "dayrep.com", "dcemail.com", "deadaddress.com", "deadletter.ga",
    "despam.it", "despammed.com", "devnullmail.com", "divermail.com",
    "dodgeit.com", "dodgit.com", "donemail.ru", "dontreg.com", "dontsendmespam.de",
    "drdrb.com", "drdrb.net", "dump-email.info", "dumpandfuck.com", "dumpmail.de",
    "dumpyemail.com", "e4ward.com", "email60.com", "emailias.com", "emailinfive.com",
    "emailsensei.com", "emailtemporario.com.br", "emailthe.net", "emailtmp.com",
    "emailwarden.com", "emailx.at.hm", "emailxfer.com", "emz.net", "enterto.com",
    "ephemail.net", "etranquil.com", "etranquil.net", "etranquil.org",
    "explodemail.com", "express.net.ua", "eyepaste.com", "fake-box.com",
    "fake-mail.cf", "fake-mail.ga", "fake-mail.ml", "fakemailgenerator.com",
    "fastacura.com", "fastchevy.com", "fastchrysler.com", "fastkawasaki.com",
    "fastmazda.com", "fastmitsubishi.com", "fastnissan.com", "fastsubaru.com",
    "fastsuzuki.com", "fasttoyota.com", "fastyamaha.com", "filzmail.com",
    "fivemail.de", "fleckens.hu", "flurre.com", "flurred.com", "frapmail.com",
    "freundin.ru", "front14.org", "fuckingduh.com", "fudgerub.com",
    "garliclife.com", "get-mail.cf", "get-mail.ga", "get-mail.ml", "get-mail.tk",
    "getairmail.com", "getmails.eu", "getonemail.com", "getonemail.net",
    "giantmail.de", "girlsundertheinfluence.com", "gishpuppy.com", "glitch.sx",
    "gomail.in", "gorillaswithdirtyarmpits.com", "greensloth.com",
    "gsrv.co.uk", "gustr.com", "harakirimail.com", "hat-geld.de", "hatespam.org",
    "herp.in", "hidemail.de", "hidzz.com", "hmamail.com", "hopemail.biz",
    "ieh-mail.de", "ihateyoualot.info", "iheartspam.org", "imails.info",
    "inbax.tk", "inbox.si", "inboxalias.com", "inboxclean.com", "inboxclean.org",
    "inboxproxy.com", "incognitomail.com", "incognitomail.net", "incognitomail.org",
    "internet.ru", "ip6.li", "ipoo.org", "irish2me.com", "iwi.net",
    "jetable.com", "jetable.fr.nf", "jetable.net", "jetable.org",
    "jnxjn.com", "jourrapide.com", "jsrsolutions.com", "junglefrog.net",
    "kasmail.com", "kaspop.com", "killmail.com", "killmail.net",
    "klassmaster.com", "klassmaster.net", "klzlk.com", "koszmail.pl",
    "kurzepost.de", "lavabit.com", "letthemeatspam.com", "lhsdv.com",
    "lifebyfood.com", "link2mail.net", "litedrop.com", "lol.ovpn.to",
    "lolfreak.net", "lookugly.com", "lortemail.dk", "lr78.com",
    "lroid.com", "lukop.dk", "m21.cc", "mail-filter.com", "mail-temporaire.fr",
    "mail.by", "mail.mezimages.net", "mail.zp.ua", "mail1a.de", "mail2rss.org",
    "mail333.com", "mailbidon.com", "mailbiz.biz", "mailblocks.com",
    "mailbucket.org", "mailcat.biz", "mailcatch.com", "mailde.de", "mailde.info",
    "maildrop.cc", "maileater.com", "mailed.ro", "maileimer.de", "mailexpire.com",
    "mailf5.com", "mailfall.com", "mailfree.ga", "mailfreeonline.com",
    "mailguard.me", "mailhazard.com", "mailhazard.us", "mailimate.com",
    "mailin8r.com", "mailinater.com", "mailinator.net", "mailinator.org",
    "mailinator.us", "mailinator2.com", "mailincubator.com", "mailismagic.com",
    "mailjunk.cf", "mailjunk.ga", "mailjunk.gq", "mailjunk.ml", "mailjunk.tk",
    "mailme.gq", "mailme.ir", "mailme.lv", "mailme24.com", "mailmetrash.com",
    "mailmoat.com", "mailms.com", "mailnew.com", "mailnull.com", "mailorg.org",
    "mailplug.info", "mailproxsy.com", "mailquack.com", "mailrock.biz",
    "mailsac.com", "mailscrap.com", "mailshell.com", "mailsiphon.com",
    "mailslapping.com", "mailslite.com", "mailtemp.info", "mailtome.de",
    "mailtothis.com", "mailtrash.net", "mailtv.net", "mailtv.tv",
    "mailvault.com", "mailw.info", "mailwire.ro", "manifestgenerator.com",
    "martinandgang.com", "mavorion.net", "mbox.re", "mciek.com",
    "meltmail.com", "messagebeamer.de", "mezimages.net", "mfsa.ru",
    "mierdamail.com", "migumail.com", "mindless.com", "mintemail.com",
    "misterpinball.de", "moburl.com", "moncourrier.fr.nf", "monemail.fr.nf",
    "monmail.fr.nf", "monumentmail.com", "mox.pp.ua", "mt2009.com",
    "mt2014.com", "mt2015.com", "mycleaninbox.net", "myemailboxy.com",
    "mymail-in.net", "mymailoasis.com", "mynetstore.de", "mypacks.net",
    "mypartyclip.de", "myphantomemail.com", "mysamp.de", "myspaceinc.com",
    "myspaceinc.net", "myspaceinc.org", "myspacepimpedup.com", "myspamless.com",
    "mytrashmail.com", "nabuma.com", "neomailbox.com", "nepwk.com",
    "nervmich.net", "nervtmich.net", "netmails.com", "netmails.net",
    "nevermail.de", "nezdiro.org", "nfmail.com", "nincsmail.hu",
    "nmail.cf", "nnh.com", "no-spam.ws", "noblepioneer.com", "nobulk.com",
    "noclickemail.com", "nomail.pw", "nomail.xl.cx", "nomail2me.com",
    "nomorespamemails.com", "nonspam.eu", "nonspammer.de", "noref.in",
    "norseforce.com", "nospam.ze.tc", "nospam4.us", "nospamfor.us",
    "nospammail.net", "nospamthanks.info", "notmailinator.com", "nwldx.com",
    "objectmail.com", "obobbo.com", "odnorazovoe.ru", "oneoffemail.com",
    "onewaymail.com", "onlatedotcom.info", "online.ms", "opayq.com",
    "ordinaryamerican.net", "otherinbox.com", "ourklips.com", "outlawspam.com",
    "ovpn.to", "owlpic.com", "pancakemail.com", "paplease.com",
    "pathfindermail.com", "pimpedupmyspace.com", "pjjkp.com", "plexolan.de",
    "poczta.onet.pl", "politikerclub.de", "pookmail.com", "postfach2go.de",
    "privacy.net", "privatdemail.net", "proxymail.eu", "prtnx.com",
    "punkass.com", "putthisinyourspamdatabase.com", "putthisinyourspamdatabase.net",
    "qq.com", "quickinbox.com", "rcpt.at", "recode.me", "recursor.net",
    "regbypass.com", "regbypass.comsafe-mail.net", "safetypost.de",
    "sandelf.de", "sendspamhere.com", "sharklasers.com", "shieldemail.com",
    "shiftmail.com", "shitmail.de", "shitmail.me", "shitmail.org",
    "shitware.nl", "shortmail.net", "sibmail.com", "sinnlos-mail.de",
    "skeefmail.com", "slapsfromlastnight.com", "slaskpost.se", "slave-auctions.net",
    "slopsbox.com", "slowslow.de", "smellfear.com", "snakemail.com",
    "sneakemail.com", "sneakmail.de", "snkmail.com", "sofimail.com",
    "sofort-mail.de", "sogetthis.com", "soisz.com", "solar-impact.pro",
    "soodonims.com", "spam-be-gone.com", "spam.care", "spam.la",
    "spam.su", "spam4.me", "spamail.de", "spambox.info", "spambox.irishspringrealty.com",
    "spambox.us", "spamcannon.com", "spamcannon.net", "spamcero.com",
    "spamcon.org", "spamcorptastic.com", "spamcowboy.com", "spamcowboy.net",
    "spamcowboy.org", "spamday.com", "spamex.com", "spamfree24.de",
    "spamfree24.eu", "spamfree24.info", "spamfree24.net", "spamfree24.org",
    "spamgoes.in", "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "spamherelots.com", "spamherelots.net", "spamhereplease.com",
    "spamhereplease.net", "spamhole.com", "spamify.com", "spaminator.de",
    "spamkill.info", "spaml.com", "spaml.de", "spammotel.com", "spamoff.de",
    "spamslicer.com", "spamspot.com", "spamthis.co.uk", "spamthisplease.com",
    "spamtrail.com", "spamtrap.ro", "speed.1s.fr", "spikio.com",
    "spoofmail.de", "squizzy.de", "squizzy.eu", "squizzy.net",
    "stinkefinger.net", "streetwisemail.com", "suburbanthug.com", "supergreatmail.com",
    "supermailer.jp", "superrito.com", "superstachel.de", "suremail.info",
    "svk.jp", "sweetxxx.de", "tafmail.com", "tagyourself.com", "tefl.ro",
    "teleworm.com", "teleworm.us", "temp-mail.de", "temp-mail.org", "temp-mail.ru",
    "tempalias.com", "tempe-mail.com", "tempemail.biz", "tempemail.co.za",
    "tempemail.com", "tempemail.net", "tempinbox.co.uk", "tempinbox.com",
    "tempmail.eu", "tempmaildemo.com", "tempmailer.com", "tempmailer.de",
    "tempomail.fr", "temporaryemail.net", "temporaryemail.us", "temporaryforwarding.com",
    "temporaryinbox.com", "temporarymailaddress.com", "tempsky.com",
    "tempthe.net", "tempymail.com", "thankyou2010.com", "thc.st",
    "thelimestones.com", "thisisnotmyrealemail.com", "thismail.net",
    "throwam.com", "throwaway.email", "throwaways.net", "throwam.com",
    "throwam.net", "tilien.com", "tittbit.in", "tizi.com", "tmailinator.com",
    "toiea.com", "toomail.biz", "tradermail.info", "trash-mail.at",
    "trash-mail.cf", "trash-mail.ga", "trash-mail.gq", "trash-mail.io",
    "trash-mail.ml", "trash-mail.tk", "trash2009.com", "trash2010.com",
    "trash2011.com", "trashdevil.com", "trashdevil.de", "trashemail.de",
    "trashimail.de", "trashmail.at", "trashmail.com", "trashmail.io",
    "trashmail.me", "trashmail.net", "trashmail.org", "trashmail.xyz",
    "trashmailer.com", "trashymail.com", "trillianpro.com", "trsh.me",
    "trud.us", "turual.com", "twinmail.de", "tyldd.com", "uggsrock.com",
    "umail.net", "unlimit.com", "unmail.ru", "uroid.com", "us.af",
    "venompen.com", "veryrealemail.com", "viditag.com", "vipmail.pw",
    "viral8.com", "vistomail.com", "vomoto.com", "vubby.com", "walkmail.net",
    "walkmail.ru", "webemail.me", "webm4il.info", "wegwerfadresse.de",
    "wegwerfemail.com", "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.info",
    "wegwerfmail.net", "wegwerfmail.org", "wh4f.org", "whatsaas.com",
    "whyspam.me", "willhackforfood.biz", "willselfdestruct.com", "winemaven.info",
    "wronghead.com", "wuzupmail.net", "www.e4ward.com", "www.gishpuppy.com",
    "www.mailinator.com", "wwwnew.eu", "xagloo.com", "xemaps.com",
    "xents.com", "xmaily.com", "xoxy.net", "xyzfree.net", "yapped.net",
    "yeah.net", "yep.it", "yogamaven.com", "yopmail.com", "yopmail.fr",
    "yourlms.biz", "ypmail.webarnak.fr.eu.org", "yuurok.com", "z1p.biz",
    "za.com", "zebins.com", "zebins.eu", "zehnminuten.de", "zehnminutenmail.de",
    "zetmail.com", "zippymail.info", "zoaxe.com", "zoemail.com", "zoemail.net",
    "zoemail.org", "zomg.info", "zoutlook.com", "zxcv.com", "zxcvbnm.com",
    "zzz.com"
}

# Role-based email prefixes
ROLE_BASED_PREFIXES = {
    "admin", "administrator", "webmaster", "postmaster", "hostmaster",
    "info", "information", "contact", "support", "help", "helpdesk",
    "sales", "marketing", "billing", "accounts", "accounting", "finance",
    "hr", "humanresources", "careers", "jobs", "recruitment", "hiring",
    "noreply", "no-reply", "donotreply", "do-not-reply", "bounce",
    "newsletter", "news", "updates", "notifications", "alerts",
    "abuse", "spam", "security", "privacy", "legal", "compliance",
    "press", "media", "pr", "publicrelations", "feedback", "service",
    "customerservice", "customer.service", "customer-service",
    "tech", "technical", "dev", "developer", "api", "system",
    "root", "mail", "email", "office", "team", "general", "enquiries",
    "enquiry", "inquiry", "inquiries"
}


def is_valid_format(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_domain(email: str) -> str:
    return email.split("@")[-1].lower() if "@" in email else ""


def is_disposable(domain: str) -> bool:
    return domain in DISPOSABLE_DOMAINS


def is_role_based(email: str) -> bool:
    prefix = email.split("@")[0].lower()
    return prefix in ROLE_BASED_PREFIXES


def check_mx_records(domain: str) -> dict:
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_list = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in records])
        return {"has_mx": True, "mx_records": [r[1] for r in mx_list]}
    except Exception:
        return {"has_mx": False, "mx_records": []}


def check_domain_exists(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except Exception:
        try:
            dns.resolver.resolve(domain, 'AAAA')
            return True
        except Exception:
            return False


def score_email(checks: dict) -> dict:
    score = 100
    risk = "low"
    reasons = []

    if not checks["is_valid_format"]:
        score -= 60
        reasons.append("Invalid email format")
    if not checks["domain_exists"]:
        score -= 40
        reasons.append("Domain does not exist")
    if not checks["has_mx_records"]:
        score -= 30
        reasons.append("No MX records found — domain cannot receive email")
    if checks["is_disposable"]:
        score -= 40
        reasons.append("Disposable/temporary email domain")
    if checks["is_role_based"]:
        score -= 10
        reasons.append("Role-based email address")

    score = max(0, score)

    if score >= 80:
        risk = "low"
    elif score >= 50:
        risk = "medium"
    else:
        risk = "high"

    return {"score": score, "risk_level": risk, "reasons": reasons}


@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {
        "name": "MailGuard API",
        "version": "1.0.0",
        "status": "live",
        "endpoints": [
            "/email/validate",
            "/email/bulk-validate",
            "/email/mx-check",
            "/email/domain-check"
        ],
        "docs": "/docs"
    }


@app.get("/email/validate")
async def validate_email(
    email: str = Query(..., description="Email address to validate")
):
    """
    Full validation of a single email address.
    Checks format, domain existence, MX records, disposable status, and role-based detection.
    Returns a quality score from 0-100 and risk level.
    """
    email = email.strip().lower()
    domain = get_domain(email)

    if not domain:
        raise HTTPException(status_code=400, detail="Invalid email address provided")

    valid_format = is_valid_format(email)
    disposable = is_disposable(domain)
    role_based = is_role_based(email)

    domain_exists = check_domain_exists(domain) if valid_format else False
    mx_data = check_mx_records(domain) if valid_format else {"has_mx": False, "mx_records": []}

    checks = {
        "is_valid_format": valid_format,
        "domain_exists": domain_exists,
        "has_mx_records": mx_data["has_mx"],
        "is_disposable": disposable,
        "is_role_based": role_based
    }

    scoring = score_email(checks)

    return {
        "email": email,
        "domain": domain,
        "is_valid": valid_format and domain_exists and mx_data["has_mx"] and not disposable,
        "checks": checks,
        "mx_records": mx_data["mx_records"],
        "quality_score": scoring["score"],
        "risk_level": scoring["risk_level"],
        "risk_reasons": scoring["reasons"],
        "suggestion": "Safe to use" if scoring["risk_level"] == "low" else "Use with caution" if scoring["risk_level"] == "medium" else "Do not use"
    }


@app.post("/email/bulk-validate")
async def bulk_validate(
    emails: List[str],
    stop_on_invalid: Optional[bool] = Query(False, description="Stop processing when first invalid email is found")
):
    """
    Validate up to 50 emails in a single request.
    Returns full validation results for each email plus a summary.
    """
    if len(emails) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 emails per bulk request")

    results = []
    valid_count = 0
    invalid_count = 0
    disposable_count = 0
    role_based_count = 0

    for email in emails:
        email = email.strip().lower()
        domain = get_domain(email)

        if not domain:
            result = {
                "email": email,
                "is_valid": False,
                "quality_score": 0,
                "risk_level": "high",
                "error": "Invalid format"
            }
            results.append(result)
            invalid_count += 1
            if stop_on_invalid:
                break
            continue

        valid_format = is_valid_format(email)
        disposable = is_disposable(domain)
        role_based = is_role_based(email)
        domain_exists = check_domain_exists(domain) if valid_format else False
        mx_data = check_mx_records(domain) if valid_format else {"has_mx": False, "mx_records": []}

        checks = {
            "is_valid_format": valid_format,
            "domain_exists": domain_exists,
            "has_mx_records": mx_data["has_mx"],
            "is_disposable": disposable,
            "is_role_based": role_based
        }
        scoring = score_email(checks)
        is_valid = valid_format and domain_exists and mx_data["has_mx"] and not disposable

        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1
        if disposable:
            disposable_count += 1
        if role_based:
            role_based_count += 1

        results.append({
            "email": email,
            "domain": domain,
            "is_valid": is_valid,
            "checks": checks,
            "quality_score": scoring["score"],
            "risk_level": scoring["risk_level"],
            "risk_reasons": scoring["reasons"]
        })

        if stop_on_invalid and not is_valid:
            break

    return {
        "total_processed": len(results),
        "summary": {
            "valid": valid_count,
            "invalid": invalid_count,
            "disposable_detected": disposable_count,
            "role_based_detected": role_based_count,
            "deliverability_rate": round((valid_count / len(results)) * 100, 1) if results else 0
        },
        "results": results
    }


@app.get("/email/mx-check")
async def mx_check(
    domain: str = Query(..., description="Domain to check MX records for, e.g. gmail.com")
):
    """
    Check MX records for a domain.
    Useful for verifying if a domain can receive emails before sending.
    """
    domain = domain.strip().lower()
    domain_exists = check_domain_exists(domain)
    mx_data = check_mx_records(domain)

    return {
        "domain": domain,
        "domain_exists": domain_exists,
        "has_mx_records": mx_data["has_mx"],
        "mx_records": mx_data["mx_records"],
        "can_receive_email": domain_exists and mx_data["has_mx"],
        "is_disposable_domain": is_disposable(domain)
    }


@app.get("/email/domain-check")
async def domain_check(
    domain: str = Query(..., description="Domain to check, e.g. google.com")
):
    """
    Full domain reputation check.
    Returns existence, MX records, disposable status, and overall domain health.
    """
    domain = domain.strip().lower()
    domain_exists = check_domain_exists(domain)
    mx_data = check_mx_records(domain)
    disposable = is_disposable(domain)

    health = "good"
    if not domain_exists:
        health = "dead"
    elif not mx_data["has_mx"]:
        health = "no-email"
    elif disposable:
        health = "disposable"

    return {
        "domain": domain,
        "domain_exists": domain_exists,
        "has_mx_records": mx_data["has_mx"],
        "mx_records": mx_data["mx_records"],
        "is_disposable": disposable,
        "domain_health": health,
        "safe_to_email": domain_exists and mx_data["has_mx"] and not disposable,
        "checked_at": datetime.utcnow().isoformat()
    }
