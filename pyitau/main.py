import requests
import json
from cached_property import cached_property

from pyitau import pages

import capsolver

import logging
from http.client import HTTPConnection
HTTPConnection.debuglevel = 1
logger = logging.getLogger('pyitau.main')

ROUTER_URL = "https://internetpf5.itau.com.br/router-app/router"

def solve_captcha(websiteURL, awsKey, awsIv, awsContext, awsChallengeJS, awsProxy = None):
        capsolver.api_key = "CAP-xxxxxxxxxxxxx"
        q = {}
        q["websiteURL"] = websiteURL
        q["awsKey"] = awsKey
        q["awsIv"] = awsIv
        q["awsContext"] = awsContext
        q["awsChallengeJS"] = awsChallengeJS
        q["type"] = "AntiAwsWafTaskProxyless"

        if awsProxy and awsProxy["http"]:
            q["type"] = "AntiAwsWafTask"
            q["proxy"] = awsProxy["http"]

        logger.debug("==== TRYING TO SOLVE 1: ====\n%s" % q)
        solution = capsolver.solve(q)
        logger.debug("==== CAPTCHA SOLUTION:\n%s" % solution)

        return solution["cookie"]

class Itau:
    def __init__(self, agency, account, account_digit, password, holder_name=None, proxy=None):
        self.agency = agency
        self.account = account
        self.account_digit = account_digit
        self.password = password
        self.holder_name = holder_name
        self._session = requests.Session()
        self._session.proxies = proxy
        self._session.headers = {
            **self._session.headers,
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Ubuntu Chromium/72.0.3626.121 "
                "Chrome/72.0.3626.121 Safari/537.36"
            ),
        }

    def authenticate(self):
        self._authenticate2()
        self._authenticate3()
        self._authenticate4()
        self._authenticate5()
        self._authenticate6()
        self._authenticate7()
        self._authenticate8()
        self._authenticate9()

    def get_credit_card_invoice(self, card_name=None):
        """
        Get and return the credit card invoice.
        """
        response = self._session.post(
            ROUTER_URL,
            headers={
                "op": self._menu_page.checking_cards_op,
                "X-FLOW-ID": self._flow_id,
                "X-CLIENT-ID": self._client_id,
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        logger.debug("===== CC INVOICE RESP:\n%s" % response.text)
        card_details = pages.CardDetails(response.text)

        response = self._session.post(
            ROUTER_URL,
            headers={"op": card_details.invoice_op},
            data={"secao": "Cartoes", "item": "Home"},
        )
        logger.debug("===== CC CARD DETAILS RESP:\n%s" % response.text)
        cards = response.json()["object"]["data"]

        res = self._session.post(
            ROUTER_URL,
            headers={"op": card_details.invoice_op},
            data={"secao": "Cartoes:MinhaFatura", "item": ""},
        )
        logger.debug("===== CC MINHA FATURA RESP:\n%s" % res.text)

        if not card_name:
            card_id = cards[0]["id"]
        else:
            card_id = next(c for c in cards if c["nome"] == card_name)["id"]

        response = self._session.post(
            ROUTER_URL, headers={"op": card_details.full_statement_op}, data=card_id
        )
        return response.json()

    def get_statements(self, days=90):
        """
        Get and return the statements of the last days.
        """
        response = self._session.post(
            ROUTER_URL,
            data={"periodoConsulta": days},
            headers={
                "op": self._checking_full_statement_page.filter_statements_by_period_op
            },
        )
        return response.json()

    def get_statements_from_month(self, month=1, year=2001):
        """
        Get and return the full statements of a specific month.
        """
        if year < 2001:
            raise Exception(f"Invalid year {year}.")

        if month < 1 or month > 12:
            raise Exception(f"Invalid month {month}.")

        response = self._session.post(
            ROUTER_URL,
            data={"mesCompleto": "%02d/%d" % (month, year)},
            headers={
                "op": self._checking_full_statement_page.filter_statements_by_month_op
            },
        )
        return response.json()

    def _authenticate2(self):
        response = self._session.post(
            ROUTER_URL,
            data={
                "portal": "005",
                "pre-login": "pre-login",
                "tipoLogon": "7",
                "usuario.agencia": self.agency,
                "usuario.conta": self.account,
                "usuario.dac": self.account_digit,
                "destino": "",
            },
        )

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate2', attempting to solve.")
            page = pages.AwsWafRouter(response.text)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate2()

        else:
            page = pages.FirstRouter(response.text)
            asdf = page.auth_token
            self._session.cookies.set("X-AUTH-TOKEN", asdf)
            self._op2 = page.secapdk
            self._op3 = page.secbcatch
            self._op4 = page.perform_request
            self._flow_id = page.flow_id
            self._client_id = page.client_id

    def _authenticate3(self):
        response = self._session.post(
            ROUTER_URL,
            headers={
                "op": self._op2,
                "X-FLOW-ID": self._flow_id,
                "X-CLIENT-ID": self._client_id,
                "renderType": "parcialPage",
                "X-Requested-With": "XMLHttpRequest",
            },
        )

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate3', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate3()


    def _authenticate4(self):
        response = self._session.post(ROUTER_URL, headers={"op": self._op3})

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate4', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate4()

    def _authenticate5(self):
        response = self._session.post(ROUTER_URL, headers={"op": self._op4})

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate5', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate5()

        else:
            page = pages.SecondRouter(response.text)
            self._op5 = page.op_sign_command
            self._op6 = page.op_maquina_pirata
            self._op7 = page.guardiao_cb

    def _authenticate6(self):
        response = self._session.post(ROUTER_URL, headers={"op": self._op5})

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate6', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate6()

    def _authenticate7(self):
        response = self._session.post(ROUTER_URL, headers={"op": self._op6})

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate7', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate7()

    def _authenticate8(self):
        response = self._session.post(ROUTER_URL, headers={"op": self._op7})

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate8', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate8()

        else:
            page = pages.ThirdRouter(response.text)

            if self.holder_name and page.has_account_holders_form:
                holder, holder_index = page.find_account_holder(self.holder_name)
                self._session.post(
                    ROUTER_URL,
                    headers={"op": page.op},
                    data={
                        "nomeTitular": holder,
                        "indexTitular": holder_index,
                    },
                )
                self._authenticate6()
                self._authenticate7()
                response = self._session.post(ROUTER_URL, headers={"op": self._op7})

                if "awswaf" in response.text:
                    logger.debug("AWS WAF detected on step '_authenticate8', attempting to solve.")
                    page = pages.AwsWafRouter(resp_txt)
                    le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
                    self._session.cookies.set("aws-waf-token", le_cookie)
                    self._authenticate8()

            page = pages.Password(response.text)
            self._letter_password = page.letter_password(self.password)
            self._op8 = page.op

    def _authenticate9(self):
        response = self._session.post(
            ROUTER_URL,
            headers={"op": self._op8},
            data={"op": self._op8, "senha": self._letter_password},
        )

        if "awswaf" in response.text:
            logger.debug("AWS WAF detected on step '_authenticate9', attempting to solve.")
            page = pages.AwsWafRouter(resp_txt)
            le_cookie = solve_captcha(ROUTER_URL, page.key, page.iv, page.context, page.challenge, self._session.proxies)
            self._session.cookies.set("aws-waf-token", le_cookie)
            self._authenticate9()

        else:
            self._home = pages.AuthenticatedHome(response.text)

    @cached_property
    def _menu_page(self):
        self._session.post(
            ROUTER_URL, headers={"op": self._home.op, "segmento": "VAREJO"}
        )
        response = self._session.post(ROUTER_URL, headers={"op": self._home.menu_op})
        return pages.Menu(response.text)

    @cached_property
    def _checking_menu_page(self):
        response = self._session.post(
            ROUTER_URL, headers={"op": self._menu_page.checking_account_op}
        )
        return pages.CheckingAccountMenu(response.text)

    @cached_property
    def _checking_statements_page(self):
        response = self._session.post(
            ROUTER_URL, headers={"op": self._checking_menu_page.statements_op}
        )
        return pages.CheckingAccountStatements(response.text)

    @cached_property
    def _checking_full_statement_page(self):
        response = self._session.post(
            ROUTER_URL,
            headers={"op": self._checking_statements_page.full_statement_op},
        )
        return pages.CheckingAccountFullStatement(response.text)
