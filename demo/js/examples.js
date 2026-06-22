// Prefilled hero example + one-click chips. Chinese-first; each chip carries its own
// text and an optional `lang` (default detection is zh+en). All values were verified to
// trigger L1 detection (>=2 entities each).
export const PREFILL = '我叫黄芳，手机号 13912345678，在北京市朝阳区建国路100号上班。';

export const CHIPS = [
  { label: '📧 客户邮件', text: '尊敬的李娜女士，您的预留手机 13800138000，邮箱 lina@example.com，如有疑问请回复。' },
  { label: '🏥 就诊记录', text: '患者王伟，38岁，电话 13712345678，住址上海市浦东新区世纪大道100号。' },
  { label: '💬 聊天', text: '我新号码 18612345678，邮箱 zhang.san@example.com，晚上来上海市徐汇区衡山路50号找我。' },
  { label: '🔤 English', text: "Hi, I'm Alice Johnson — call me at (415) 555-0163 or alice@example.com.", lang: ['en'] },
];
