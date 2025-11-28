// stylelint.config.cjs
module.exports = {
    // 要檢查的檔案類型
    extends: [
        'stylelint-config-standard', // 標準 CSS 規則
    ],
    overrides: [
        {
            files: ['*.scss'],
            customSyntax: 'postcss-scss',
        },
        {
            files: ['*.less'],
            customSyntax: 'postcss-less',
        },
    ],
    rules: {
        /* 基本通用規則（偏嚴謹但不至於太吵） */

        // 色碼、字串等風格
        'color-hex-length': 'short',
        'font-family-name-quotes': 'always-where-required',
        'function-url-quotes': 'always',

        // 區塊與宣告
        'block-no-empty': true,
        'declaration-block-no-duplicate-properties': [
            true,
            {
                ignore: ['consecutive-duplicates-with-different-values'],
            },
        ],

        // 不安全／deprecated 用法
        'color-named': 'never',
        'function-linear-gradient-no-nonstandard-direction': true,

        // 選擇器
        // Project relies on structured IDs from the single-page app layout; relax ID limits.
        'selector-max-id': null,
        'selector-max-universal': 1,
        'selector-max-compound-selectors': 4,
        'selector-max-class': 4,
        'selector-no-qualifying-type': null, // 避免太嚴，class+tag 常見

        // @ 規則
        'at-rule-no-unknown': null, // 交給 SCSS / Less config 處理（@mixin, @include 等）
        'at-rule-empty-line-before': [
            'always',
            {
                except: ['blockless-after-same-name-blockless', 'first-nested'],
                ignore: ['after-comment'],
            },
        ],

        // 禁止使用 !important（如果你專案真的用很多，可以改成 'warn' 或關掉）
        'declaration-no-important': null,

        // Allow existing camelCase IDs used by the wasm UI.
        'selector-id-pattern': null,

        // 其他噪音較大的規則適度關閉
        'no-descending-specificity': null,
        'selector-class-pattern': null,
    },
};
