(() => {
  const shouldRemoveAttribute = (name) => {
    return (
      name === 'bis_skin_checked'
      || name === 'bis_register'
      || name === 'monica-id'
      || name === 'monica-version'
      || name.startsWith('data-darkreader-')
      || name.startsWith('__processed_')
    );
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
    cleanNode(document.body);

    if (!document.body) {
      return;
    }

    Array.from(document.body.getElementsByTagName('*')).forEach(cleanNode);
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

        if (typeof node.getElementsByTagName === 'function') {
          Array.from(node.getElementsByTagName('*')).forEach(cleanNode);
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

  if (!document.body) {
    document.addEventListener('DOMContentLoaded', cleanTree, { once: true });
  }
})();
