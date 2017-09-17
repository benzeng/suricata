/* Copyright (C) 2015-2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-tds.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectTdsRegister below */
static int DetectTdsMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTdsSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTdsFree (void *);
static void DetectTdsRegisterTests (void);



/**
 * \brief Registration function for tds: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectTdsRegister(void) 
{
    /* keyword name: this is how the keyword is used in a rule */
    //sigmatch_table[DETECT_TDS].name = "tds";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_TDS].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_TDS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_TDS].Match = DetectTdsMatch;
    /* setup function is called during signature parsing, when the tds
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_TDS].Setup = DetectTdsSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_TDS].Free = DetectTdsFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_TDS].RegisterTests = DetectTdsRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match TDS rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectTdsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTdsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectTdsData *tdsd = (const DetectTdsData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (tdsd->arg1 == p->payload[0] &&
            tdsd->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse tds options passed via tds: keyword
 *
 * \param tdsstr Pointer to the user provided tds options
 *
 * \retval tdsd pointer to DetectTdsData on success
 * \retval NULL on failure
 */
static DetectTdsData *DetectTdsParse (const char *tdsstr)
{
    DetectTdsData *tdsd = NULL;
    char arg1[4] = "";
    char arg2[4] = "";
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    tdsstr, strlen(tdsstr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) tdsstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) tdsstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

    }

    tdsd = SCMalloc(sizeof (DetectTdsData));
    if (unlikely(tdsd == NULL))
        goto error;
    tdsd->arg1 = (uint8_t)atoi(arg1);
    tdsd->arg2 = (uint8_t)atoi(arg2);

    return tdsd;

error:
    if (tdsd)
        SCFree(tdsd);
    return NULL;
}

/**
 * \brief parse the options from the 'tds' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param tdsstr pointer to the user provided tds options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTdsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *tdsstr)
{
    DetectTdsData *tdsd = NULL;
    SigMatch *sm = NULL;

    tdsd = DetectTdsParse(tdsstr);
    if (tdsd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TDS;
    sm->ctx = (void *)tdsd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (tdsd != NULL)
        DetectTdsFree(tdsd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectTdsData
 *
 * \param ptr pointer to DetectTdsData
 */
static void DetectTdsFree(void *ptr) {
    DetectTdsData *tdsd = (DetectTdsData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(tdsd);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectTdsParseTest01 (void)
{
    DetectTdsData *tdsd = DetectTdsParse("1,10");
    FAIL_IF_NULL(tdsd);
    FAIL_IF(!(tdsd->arg1 == 1 && tdsd->arg2 == 10));
    DetectTdsFree(tdsd);
    PASS;
}

static int DetectTdsSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (tds:1,10; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTds
 */
void DetectTdsRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectTdsParseTest01", DetectTdsParseTest01);
    UtRegisterTest("DetectTdsSignatureTest01",
                   DetectTdsSignatureTest01);
#endif /* UNITTESTS */
}
