// Preloaded with `node --import`: resolves the `thousandeyes` import in ldap-monitor.js to the
// local stub, so the deployable script runs unmodified outside ThousandEyes.
import { registerHooks } from 'node:module';

const stubUrl = new URL('./thousandeyes-stub.js', import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'thousandeyes') return { url: stubUrl, format: 'module', shortCircuit: true };
    return nextResolve(specifier, context);
  },
});
