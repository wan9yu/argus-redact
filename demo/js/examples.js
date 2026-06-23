// Prefilled hero example + one-click chips. Chinese-first; each chip carries its own
// text and an optional `lang` (default detection is zh+en). All values were verified to
// trigger L1 detection (>=2 entities each). The set showcases the v0.7.x breadth beyond
// formatted identifiers: occupation, medical condition/allergy, hobby, and bare region —
// all from regex + evidence-gated detectors, no model, fully in-browser.
export const PREFILL = '我叫黄芳，是一名设计师，对花粉过敏，平时喜欢摄影，手机号 13912345678。';

export const CHIPS = [
  { label: '📧 客户邮件', text: '尊敬的李娜女士，您的预留手机 13800138000，邮箱 lina@example.com，如有疑问请回复。' },
  { label: '🏥 就诊记录', text: '患者王伟，38岁，确诊糖尿病，对头孢过敏，住址上海市浦东新区世纪大道100号。' },
  { label: '🧑‍💻 个人简介', text: '我是一名软件工程师，平时喜欢攀岩和摄影，邮箱 wang.gong@example.com。' },
  { label: '💬 聊天', text: '我新号码 18612345678，邮箱 zhang.san@example.com，晚上来上海市徐汇区衡山路50号找我。' },
  { label: '🔤 English', text: "Hi, I'm Alice Johnson — call me at (415) 555-0163 or alice@example.com.", lang: ['en'] },
];
