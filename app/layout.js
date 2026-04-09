import './globals.css';
import { getAppOrigin } from '../lib/server/config';

const appOrigin = getAppOrigin();
const socialImagePath = '/assets/images/phase-logo.png';

export const metadata = {
  title: 'Phase Vuln Coach',
  description: 'Phase Vuln Coach Next.js application',
  metadataBase: new URL(appOrigin),
  openGraph: {
    title: 'Phase Vuln Coach',
    description: 'Phase Vuln Coach Next.js application',
    url: appOrigin,
    siteName: 'Phase Vuln Coach',
    images: [
      {
        url: socialImagePath,
        alt: 'Phase logo',
      },
    ],
    locale: 'ko_KR',
    type: 'website',
  },
  twitter: {
    card: 'summary',
    title: 'Phase Vuln Coach',
    description: 'Phase Vuln Coach Next.js application',
    images: [socialImagePath],
  },
};

const extensionHydrationCleanup = `
(() => {
  const shouldIgnoreHydrationConsoleError = (args) => {
    const joined = args
      .map((value) => {
        if (typeof value === 'string') {
          return value;
        }

        try {
          return JSON.stringify(value);
        } catch {
          return String(value);
        }
      })
      .join(' ');

    return (
      joined.includes('A tree hydrated but some attributes of the server rendered HTML')
      || joined.includes("didn't match the client properties")
      || joined.includes('https://react.dev/link/hydration-mismatch')
      || joined.includes('https://nextjs.org/docs/messages/react-hydration-error')
    );
  };

  let delegatedConsoleError = console.error.bind(console);
  const wrappedConsoleError = (...args) => {
    if (shouldIgnoreHydrationConsoleError(args)) {
      return;
    }

    delegatedConsoleError(...args);
  };

  Object.defineProperty(console, 'error', {
    configurable: true,
    enumerable: true,
    get() {
      return wrappedConsoleError;
    },
    set(nextValue) {
      delegatedConsoleError = typeof nextValue === 'function'
        ? nextValue.bind(console)
        : (...args) => {};
    },
  });

  const shouldRemoveAttribute = (name) => (
    name === 'bis_skin_checked'
    || name === 'bis_register'
    || name === 'monica-id'
    || name === 'monica-version'
    || name.startsWith('data-darkreader-')
    || name.startsWith('__processed_')
  );

  const originalSetAttribute = Element.prototype.setAttribute;
  const originalSetAttributeNS = Element.prototype.setAttributeNS;

  Element.prototype.setAttribute = function setAttribute(name, value) {
    if (shouldRemoveAttribute(String(name || ''))) {
      return;
    }

    return originalSetAttribute.call(this, name, value);
  };

  Element.prototype.setAttributeNS = function setAttributeNS(namespace, name, value) {
    if (shouldRemoveAttribute(String(name || ''))) {
      return;
    }

    return originalSetAttributeNS.call(this, namespace, name, value);
  };

  const cleanNode = (node) => {
    if (!node || typeof node.getAttributeNames !== 'function') {
      return;
    }

    node.getAttributeNames().forEach((name) => {
      if (shouldRemoveAttribute(name)) {
        node.removeAttribute(name);
      }
    });
  };

  const cleanTree = () => {
    cleanNode(document.documentElement);
    Array.from(document.querySelectorAll('*')).forEach(cleanNode);
  };

  cleanTree();

  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'attributes') {
        cleanNode(mutation.target);
        return;
      }

      mutation.addedNodes.forEach((node) => {
        if (!node || node.nodeType !== Node.ELEMENT_NODE) {
          return;
        }

        cleanNode(node);
        if (typeof node.querySelectorAll === 'function') {
          Array.from(node.querySelectorAll('*')).forEach(cleanNode);
        }
      });
    });
  });

  observer.observe(document.documentElement, {
    attributes: true,
    childList: true,
    subtree: true,
  });

  window.addEventListener('load', () => observer.disconnect(), { once: true });
})();
`;

export default function RootLayout({ children }) {
  return (
    <html lang="ko" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{ __html: extensionHydrationCleanup }}
        />
      </head>
      <body suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
