"""Chinese surname data — shared by patterns.py and person.py."""

# Top 500 Chinese surnames (covers ~99% of population)
SURNAMES = (
    "王李张刘陈杨赵黄周吴徐孙胡朱高林何郭马罗"
    "梁宋郑谢韩唐冯于董萧程曹袁邓许傅沈曾彭吕"
    "苏卢蒋蔡贾丁魏薛叶阎余潘杜戴夏钟汪田任姜"
    "范方石姚谭廖邹熊金陆郝孔白崔康毛邱秦江史顾"
    "侯邵孟龙万段漕钱汤尹黎易常武乔贺赖龚文庞"
    "樊兰殷施陶洪翟安颜倪严牛温芦季俞章鲁葛伍"
    "韦申尤毕聂丛焦向柳邢骆岳齐沿雷詹欧"
)

SURNAME_SET = frozenset(SURNAMES)

# Compound surnames (2 chars)
COMPOUND_SURNAMES = frozenset({
    "欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "令狐", "公孙",
    "慕容", "尉迟", "长孙", "宇文", "司徒", "端木", "南宫", "西门",
})
