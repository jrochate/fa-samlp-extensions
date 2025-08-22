package pt.adj3.keycloak.idp;

import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Fornecedor de Autenticacao SAML Extensions
 * -----------------------------------------
 * Keycloak 26.3.1 preprocessor that injects the Autenticacao.gov (Cartão de Cidadão)
 * required <samlp:Extensions> block into outgoing AuthnRequests.
 *
 * v1 scope (intentionally small & safe):
 *  - Hard-coded RequestedAttributes:
 *      - http://interop.gov.pt/MDC/Cidadao/NomeCompleto
 *      - http://interop.gov.pt/MDC/Cidadao/NIF
 *      - http://interop.gov.pt/MDC/Cidadao/CorreioElectronico
 *  - Hard-coded <fa:FAAALevel>3</fa:FAAALevel>
 *  - No UI/config yet (planned for v2).
 *
 * Implementation details:
 *  - Uses DocumentUtil to parse small XML fragments that already include xmlns:fa.
 *    This avoids namespace/attribute serialization pitfalls during SAML write-out.
 *  - Never throws (surrounded by try/catch) so login cannot be broken by this hook.
 *
 * If you later want to scope this to a single IdP alias, see the commented block below.
 */
public class FaSamlpExtensionsPreprocessor implements SamlAuthenticationPreprocessor {

    /** Official FA namespace used by Autenticacao.gov for SAML extensions. */
    private static final String FA_NS = "http://autenticacao.cartaodecidadao.pt/atributos";

    // -------------------------------------------------------------------------
    // ProviderFactory (KC 26.x requires preprocessor to act as both factory+provider)
    // -------------------------------------------------------------------------

    /** A short, stable id for this preprocessor. */
    @Override
    public String getId() {
        return "fa-samlp-extensions";
    }

    /** Factory method; returns a new instance used during requests. */
    @Override
    public SamlAuthenticationPreprocessor create(KeycloakSession session) {
        return new FaSamlpExtensionsPreprocessor();
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // v1: no configuration yet
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // You can log here if you want a startup marker:
        // System.out.println("[fa-samlp-extensions] preprocessor loaded");
    }

    @Override
    public void close() {
        // nothing to cleanup
    }

    // -------------------------------------------------------------------------
    // Main hook: enrich the outgoing AuthnRequest
    // -------------------------------------------------------------------------

    @Override
    public AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest,
                                                      AuthenticationSessionModel clientSession) {
        try {
            // --- Optional scoping (disabled in v1) ---
            // If you only want to apply this when brokering to a specific IdP alias,
            // you can set/read an auth note earlier in your flow and check it here.
            // Example (pseudocode):
            // String alias = clientSession != null ? clientSession.getAuthNote("identity_provider") : null;
            // if (alias != null && !alias.equals("autenticacao.gov")) return authnRequest;

            // Ensure <Extensions> exists
            ExtensionsType ext = authnRequest.getExtensions();
            if (ext == null) {
                ext = new ExtensionsType();
                authnRequest.setExtensions(ext);
            }

            // Build the FA XML fragments as strings; include xmlns:fa on each top-level element.
            String requestedXml =
                "<fa:RequestedAttributes xmlns:fa=\"" + FA_NS + "\">" +
                "  <fa:RequestedAttribute Name=\"http://interop.gov.pt/MDC/Cidadao/NomeCompleto\" " +
                "                         NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" " +
                "                         isRequired=\"true\"/>" +
                "  <fa:RequestedAttribute Name=\"http://interop.gov.pt/MDC/Cidadao/NIF\" " +
                "                         NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" " +
                "                         isRequired=\"true\"/>" +
                "  <fa:RequestedAttribute Name=\"http://interop.gov.pt/MDC/Cidadao/CorreioElectronico\" " +
                "                         NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" " +
                "                         isRequired=\"true\"/>" +
                "</fa:RequestedAttributes>";

            String levelXml =
                "<fa:FAAALevel xmlns:fa=\"" + FA_NS + "\">3</fa:FAAALevel>";

            // Parse fragments with Keycloak helper (namespace-aware)
            Document reqDoc = DocumentUtil.getDocument(requestedXml);
            Document lvlDoc = DocumentUtil.getDocument(levelXml);

            Element requestedEl = reqDoc.getDocumentElement();
            Element levelEl = lvlDoc.getDocumentElement();

            // Attach to the AuthnRequest <Extensions>
            ext.addExtension(requestedEl);
            ext.addExtension(levelEl);

        } catch (Exception ignored) {
            // Intentionally swallow: do not break authentication on extension failure
            // If you want diagnostics during testing, temporarily log here.
            // System.err.println("[fa-samlp-extensions] failed to inject extensions: " + ignored);
        }
        return authnRequest;
    }
}
