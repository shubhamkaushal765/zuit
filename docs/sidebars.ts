import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    'intro',
    'quickstart',
    {
      type: 'category',
      label: 'Workflows',
      collapsed: false,
      items: [
        'workflows/daily-dev-loop',
        'workflows/gate-ci',
        'workflows/adopt-legacy',
        'workflows/track-trends',
      ],
    },
    {
      type: 'category',
      label: 'Concepts',
      items: [
        'concepts/dimensions',
        'concepts/analyzers-and-findings',
        'concepts/severity-and-scoring',
      ],
    },
    {
      type: 'category',
      label: 'CLI reference',
      items: [
        'cli/analyze',
        'cli/list',
        'cli/init',
        'cli/show',
        'cli/report',
        'cli/diff',
        'cli/baseline',
        'cli/watch',
        'cli/install-hook',
        'cli/lsp',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'configuration/zuit-toml',
        'configuration/per-rule-config',
        'configuration/baselines-and-fail-on',
      ],
    },
    {
      type: 'category',
      label: 'Output formats',
      items: [
        'output/terminal',
        'output/json',
        'output/json-schema',
        'output/markdown',
        'output/sarif',
        'output/checkstyle',
        'output/junit',
      ],
    },
    {
      type: 'category',
      label: 'Rules reference',
      link: { type: 'doc', id: 'rules/index' },
      items: [
        'rules/suppression',
        {
          type: 'category',
          label: 'Bug',
          items: [
            'rules/BUG001-assignment-in-condition',
            'rules/BUG002-switch-fallthrough',
            'rules/BUG004-operator-precedence',
          ],
        },
        {
          type: 'category',
          label: 'Maintainability',
          items: [
            'rules/MAINT001-cyclomatic',
            'rules/MAINT002-cognitive',
            'rules/MAINT003-fn-length',
            'rules/MAINT004-file-length',
            'rules/MAINT005-deep-nesting',
            'rules/MAINT006-too-many-params',
            'rules/MAINT007-return-complexity',
          ],
        },
        {
          type: 'category',
          label: 'Security',
          items: [
            'rules/SEC001-hardcoded-secret',
            'rules/SEC002-eval-sink',
            'rules/SEC003-shell-injection',
            'rules/SEC004-weak-crypto',
            'rules/SEC005-insecure-deser',
            'rules/SEC006-sql-injection',
            'rules/SEC007-path-traversal',
            'rules/SEC012-hardcoded-security-constant',
            'rules/SEC013-bind-all-interfaces',
            'rules/SEC014-redos-regex',
            'rules/SEC015-log-injection',
            'rules/SEC016-dangerous-function',
            'rules/SEC101-rust-unsafe',
          ],
        },
        {
          type: 'category',
          label: 'Complexity',
          items: [
            'rules/CPLX001-fan-out',
            'rules/CPLX002-cyclic-deps',
            'rules/CPLX003-duplicate-code',
          ],
        },
        {
          type: 'category',
          label: 'Documentation',
          items: [
            'rules/DOC001-public-api-undoc',
            'rules/DOC002-todo-fixme',
            'rules/DOC003-empty-doc',
          ],
        },
        {
          type: 'category',
          label: 'Test smell',
          items: [
            'rules/TEST001-test-ratio',
            'rules/TEST002-no-asserts',
            'rules/TEST003-skipped',
            'rules/TEST004-flaky-time',
            'rules/TEST005-assert-count',
          ],
        },
        {
          type: 'category',
          label: 'Dependencies',
          items: [
            'rules/DEP001-vulnerable-deps',
          ],
        },
        {
          type: 'category',
          label: 'API stability',
          items: [
            'rules/API001-public-symbol-removed',
            'rules/API002-signature-arity-changed',
            'rules/API003-semver-alignment',
          ],
        },
        {
          type: 'category',
          label: 'Supply chain',
          items: [
            'rules/CHAIN001-no-lockfile',

            'rules/CHAIN002-typosquat-suspicion',
            'rules/CHAIN003-git-dependency-without-rev',

            'rules/CHAIN003-provenance-bundle-missing',
            'rules/CHAIN004-path-dependency-in-published-crate',
            'rules/CHAIN004-unpinned-runtime-dep',

            'rules/CHAIN004-unmaintained-transitive',
          ],
        },
        {
          type: 'category',
          label: 'CI/CD',
          items: [
            'rules/CI001-no-ci-config',
            'rules/CI002-no-msrv-test-job',
            'rules/CI003-no-windows-job',
            'rules/CI004-no-cargo-deny-job',
            'rules/CI005-no-dependabot',
            'rules/CI006-warnings-not-denied',
          ],
        },
        {
          type: 'category',
          label: 'Documentation (extra)',
          items: [
            'rules/DOC004-stale-doc',
          ],
        },
        {
          type: 'category',
          label: 'Ecosystem',
          items: [
            'rules/ECO001-no-no-std-feature',
            'rules/ECO002-async-runtime-coupling',
            'rules/ECO003-send-sync-violations-on-pub-types',
            'rules/ECO004-feature-graph-fragmented',
          ],
        },
        {
          type: 'category',
          label: 'Health',
          items: [
            'rules/HEALTH001-single-author',
            'rules/HEALTH002-stale-release',
            'rules/HEALTH003-low-bus-factor',
            'rules/HEALTH004-commit-stale',
            'rules/HEALTH005-changelog-missing',
          ],
        },
        {
          type: 'category',
          label: 'Maintainability (extra)',
          items: [
            'rules/MAINT008-large-impl-block',
            'rules/MAINT009-missing-default-case',
            'rules/MAINT010-infinite-loop-no-exit',
            'rules/MAINT011-active-debug-code',
            'rules/MAINT012-dead-store',
            'rules/MAINT013-empty-block',
            'rules/MAINT014-commented-out-code',
            'rules/MAINT015-deprecated-function',
            'rules/MAINT016-unreachable-code',
            'rules/MAINT018-global-var-density',
            'rules/MAINT019-unconditional-branch',
            'rules/STYLE001-block-delimitation',
          ],
        },
        {
          type: 'category',
          label: 'Performance',
          items: [
            'rules/PERF001-bundle-size',
            'rules/PERF001-heavy-default-features',
            'rules/PERF001-heavy-import',
            'rules/PERF002-clone-in-iter-chain',
            'rules/PERF002-heavy-import',
            'rules/PERF002-wheel-size',
            'rules/PERF003-arc-mutex-density',
            'rules/PERF003-import-side-effect',
            'rules/PERF010-allocation-in-loop',
          ],
        },
        {
          type: 'category',
          label: 'Packaging',
          items: [
            'rules/PKG001-install-script-present',
            'rules/PKG001-invalid-cargo-toml',
            'rules/PKG001-invalid-pyproject',
            'rules/PKG002-license-not-declared',
            'rules/PKG002-metadata-incomplete',
            'rules/PKG002-missing-types',
            'rules/PKG003-description-missing',
            'rules/PKG003-dual-package-hazard',
            'rules/PKG003-legacy-build-backend',
            'rules/PKG004-license-not-declared',
            'rules/PKG004-repository-missing',
            'rules/PKG004-unpinned-deps',
            'rules/PKG005-engines-missing',
            'rules/PKG005-python-version-unconstrained',
            'rules/PKG005-rust-version-unconstrained',
            'rules/PKG006-readme-missing',
            'rules/PKG007-version-mismatch',
            'rules/PKG008-entry-points-malformed',
            'rules/PKG008-keywords-categories-missing',
            'rules/PKG009-classifiers-missing',
            'rules/PKG009-default-features-bloat',
            'rules/PKG010-dynamic-version-unstable',
            'rules/PKG010-workspace-inheritance-broken',
          ],
        },

        {
          type: 'category',
          label: 'Plugin rules',
          items: [
            'rules/PLUGIN',
          ],
        },

        {
          type: 'category',
          label: 'Security (extra)',
          items: [
            'rules/SEC008-csrf-missing',
            'rules/SEC009-open-redirect',
            'rules/SEC010-ssrf',
            'rules/SEC011-cors-permissive',
          ],
        },
        {
          type: 'category',
          label: 'Soundness',
          items: [
            'rules/SOUND001-unsafe-block-missing-safety-comment',
            'rules/SOUND002-unsafe-in-pub-api-signature',
            'rules/SOUND003-transmute-usage',
            'rules/SOUND004-raw-pointer-in-pub-api',
            'rules/SOUND005-unsafe-and-parsing-combo',
            'rules/SOUND006-ffi-without-safety-doc',
          ],
        },
        {
          type: 'category',
          label: 'Test smell (extra)',
          items: [
            'rules/TEST006-shared-mutable-state',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Integrations',
      items: [
        'integrations/github-action',
        'integrations/lsp',
      ],
    },
    {
      type: 'category',
      label: 'Extending',
      items: [
        'extending/add-a-language',
        'extending/add-an-analyzer',
        'extending/plugins',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/taxonomy',
      ],
    },
    'architecture',
  ],
};

export default sidebars;
