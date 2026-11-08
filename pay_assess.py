#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pay_assess.py —— 支付系统攻击面评估器
============================================================
不是"平台名单"，是**模型**：输入目标的技术画像 → 输出该测什么、怎么测、用哪个 PoC。

为什么比清单有用：
  · 清单会过期，模型不会
  · 模型会告诉你**优先级**（哪个先测收益最高）
  · 每条结论都对应一个可跑的 PoC 或一个判定方法

用法：
  python3 pay_assess.py --preset ecommerce
  python3 pay_assess.py --preset gambling --json
  python3 pay_assess.py --interactive          # 问答式生成画像
  python3 pay_assess.py --profile my.yaml      # 自定义画像
"""
import argparse
import json
import sys

# ---------------------------------------------------------------- 画像字段
FIELDS = {
    "biz":        ("业务类型", ["ecommerce", "subscription", "gambling", "remittance",
                              "wallet", "marketplace", "saas", "indie"]),
    "pay_method": ("支付方式", ["card", "local_wallet", "bank_transfer", "crypto",
                              "giftcard", "carrier_billing", "mixed"]),
    "settle":     ("结算模式", ["direct", "acquirer", "pg", "aggregator", "split"]),
    "currency":   ("币种", ["single", "multi", "dcc"]),
    "risk":       ("风控", ["none", "rules", "third_party", "ml"]),
    "recon":      ("对账", ["none", "t1", "t0", "realtime"]),
    "refund":     ("退款路径", ["original", "fallback", "wallet", "manual"]),
    "split":      ("分账", ["none", "single", "multi_level"]),
    "preauth":    ("预授权", ["none", "hotel", "rental", "custom"]),
    "subscribe":  ("订阅/续费", ["none", "auto", "manual"]),
    "affiliate":  ("联盟/推广", ["none", "coupon", "points", "multi_tier"]),
    "payout":     ("出金", ["manual", "auto", "hybrid"]),
    "kyc":        ("KYC", ["none", "basic", "tiered", "full"]),
    "tds":        ("3DS", ["none", "optional", "mandatory"]),
    "token":      ("令牌化", ["none", "network", "custom"]),
    "device":     ("设备指纹", ["none", "basic", "advanced"]),
}

# ---------------------------------------------------------------- 规则库
# (画像条件, 风险ID, 标题, 影响, 验证方法, PoC/参考)
RULES = [
 # ---- 资金归属类（最高优先）
 (lambda p: p["split"] == "multi_level", "F1", "多级分账的资金穿透",
  "二级资金被一级连带冻结/挪用", "查二级是否有独立实体账户；冻结一级看二级是否可用",
  "edge/l4/l4_32_fund_penetration.py"),
 (lambda p: p["settle"] in ("aggregator", "split"), "F2", "二清风险",
  "平台代收代付被认定无证清算", "看资金是否进平台自有账户；查备付金存管",
  "edge/l4/l4_32_fund_penetration.py"),
 (lambda p: p["recon"] in ("none", "t1"), "F3", "三方账期时差",
  "同一笔钱在多本账上同时可用", "对比商户/平台/银行三方可用余额口径",
  "edge/l4/l4_28_three_way_recon.py"),
 (lambda p: p["payout"] in ("auto", "hybrid"), "F4", "出金链路自动化滥用",
  "自动出金被用于洗钱/套现", "测出金账户变更是否需二次确认；查限额",
  "edge/l4/l4_21_cancelled_card_refund.py"),
 (lambda p: p["refund"] in ("fallback", "wallet"), "F5", "退款到非原账户",
  "钱被退给攻击者控制的账户", "测原卡注销后的兜底路由；查收款账户是否可指定",
  "edge/l4/l4_21_cancelled_card_refund.py"),

 # ---- 计费/费率类
 (lambda p: p["currency"] == "dcc", "C1", "DCC 隐藏加价",
  "用户多付且无法判断 markup", "抓汇率字段，算 markup 百分比",
  "edge/l4/l4_23_dcc_markup.py"),
 (lambda p: p["currency"] == "multi", "C2", "结算币种错配",
  "汇率风险错配给无定价权一方", "查取价时点（下单/结算）；算 5% 分位损失",
  "edge/l4/l4_29_fx_mismatch.py"),
 (lambda p: p["subscribe"] == "auto", "C3", "订阅续费与退款不同步",
  "取消后仍扣款 / 退款不退订阅", "测取消→扣款时序；测退款后权益是否回收",
  "edge/l4/l4_27_cap_points_arb.py"),
 (lambda p: p["preauth"] != "none", "C4", "预授权超时释放",
  "额度被用两次", "测释放与请款顺序；测窗口内能否再消费",
  "edge/l4/l4_24_preauth_release.py"),

 # ---- 营销/积分类
 (lambda p: p["affiliate"] in ("coupon", "points", "multi_tier"), "M1", "优惠券/积分套利",
  "刷券、刷积分、拉新返利被薅", "测并发领取、测退款后积分是否回滚",
  "edge/l4/l4_27_cap_points_arb.py"),
 (lambda p: p["affiliate"] == "multi_tier", "M2", "多级分销的资金池混用",
  "下级资金与平台运营资金混同", "查分销账户是否隔离",
  "edge/l4/l4_32_fund_penetration.py"),

 # ---- 认证/风控类
 (lambda p: p["tds"] == "none", "A1", "无 3DS 的卡交易",
  "盗卡直接过，拒付风险全在商户", "测 3DS 四道门（状态/ECI/CAVV/绑定）",
  "edge/l4/l4_14_3ds_bypass.py"),
 (lambda p: p["tds"] == "optional", "A2", "3DS 可降级",
  "攻击者强制走无 3DS 通道", "测降级请求是否被接受",
  "edge/l4/l4_14_3ds_bypass.py"),
 (lambda p: p["risk"] in ("none", "rules"), "A3", "风控规则可枚举",
  "规则阈值被摸出来绕过", "测临界金额/频次；测设备指纹缺失",
  "edge/l4/l4_3_risk_model_poison.py"),
 (lambda p: p["kyc"] in ("none", "basic"), "A4", "KYC 分级可绕过",
  "低等级账户做高等级操作", "测等级边界；测资料伪造是否被接受",
  "edge/l4/l4_1_agent_taint.py"),

 # ---- 技术实现类
 (lambda p: p["pay_method"] == "card", "T1", "卡数据与 PIN 处理",
  "PIN block 格式混用/可重放", "比对 ISO-0 vs ISO-3；测重放",
  "edge/l4/l4_18_pinblock_format.py"),
 (lambda p: p["pay_method"] == "card", "T2", "磁条降级",
  "芯片卡被降级为磁条，克隆可用", "测 fallback 是否被允许；测 iCVV",
  "edge/l4/l4_17_magstripe_downgrade.py"),
 (lambda p: p["pay_method"] in ("local_wallet", "card"), "T3", "NFC/近场中继",
  "距离绑定被中继绕过", "测 RTT 检测阈值；测多跳延迟",
  "edge/l4/l4_16_nfc_relay.py"),
 (lambda p: p["token"] == "custom", "T4", "自定义令牌化",
  "令牌可预测/可跨商户复用", "测令牌生成随机性；测跨商户使用",
  "weak/crypto_attack.py"),
 (lambda p: p["biz"] in ("ecommerce", "marketplace", "indie"), "T5", "分账规则注入",
  "多分出一份给攻击者", "测分账总和是否必须 100%；测精度变体",
  "edge/l4/l4_20_split_injection.py"),
 (lambda p: True, "T6", "金额与取整边界",
  "浮点/取整差额被系统性利用", "用最小单位整数对账；测 0.01 边界",
  "edge/l4/l4_22_dual_billing.py"),

 # ---- 业务逻辑类
 (lambda p: p["biz"] == "gambling", "B1", "博彩的充提闭环",
  "充值-下注-提现链路被套利/洗钱", "测充值到账时序；测提现审核绕过；测对冲下注",
  "edge/l4/l4_25_refund_chargeback.py"),
 (lambda p: p["biz"] == "gambling", "B2", "奖金池与流水要求",
  "流水门槛被绕过（对冲/低风险下注）", "测对冲是否计入流水；测最低赔率下注",
  "edge/l4/l4_12_settlement_arb.py"),
 (lambda p: p["biz"] in ("ecommerce", "indie"), "B3", "虚拟商品交付与退款",
  "拿到货再退款（虚拟品无法追回）", "测发货与退款的原子性；测卡密重复使用",
  "edge/l4/l4_25_refund_chargeback.py"),
 (lambda p: p["biz"] == "remittance", "B4", "跨境汇款与汇率锁定",
  "锁价窗口被当免费期权", "测锁价时长与波动；算期望损失",
  "edge/l4/l4_26_fx_lock_expiry.py"),
 (lambda p: p["biz"] == "wallet", "B5", "钱包余额与提现",
  "余额可被并发扣减/负数", "测并发提现；测余额快照与流水一致性",
  "edge/l4/l4_30_reserve_pool.py"),

 # ---- 运营/数据类
 (lambda p: True, "O1", "对账缺失或只看总额",
  "差异被压到阈值内长期不被发现", "查是否有明细级对账；测小额差异累积",
  "edge/l4/l4_28_three_way_recon.py"),
 (lambda p: True, "O2", "后台权限与操作审计",
  "客服/运营可改金额、可查全量数据", "测角色边界；测操作日志完整性",
  "edge/l4/l4_19_tid_reuse.py"),
 (lambda p: p["device"] == "none", "O3", "无设备指纹的多账号",
  "一人多号刷活动/刷返利", "测同设备多账号；测指纹可伪造",
  "edge/l4/l4_3_risk_model_poison.py"),
 (lambda p: p["pay_method"] == "crypto", "O4", "链上地址与到账确认",
  "假充值（未确认即到账）/ 双花", "测确认数阈值；测替换交易",
  "edge/l4/l4_13_iso8583_misparse.py"),
 (lambda p: p["pay_method"] == "giftcard", "O5", "礼品卡/卡密体系",
  "卡密可枚举、可重复兑换", "测卡密熵；测兑换幂等",
  "edge/l4/l4_33_offline_batch_dup.py"),
]

SEVERITY = {"F": ("🔴 资金", 1), "C": ("🟠 计费", 2), "A": ("🟠 认证", 2),
            "B": ("🟡 业务", 3), "M": ("🟡 营销", 3), "T": ("🟡 技术", 3),
            "O": ("⚪ 运营", 4)}

PRESETS = {
    "ecommerce": {"biz":"ecommerce","pay_method":"mixed","settle":"pg","currency":"multi",
                  "risk":"rules","recon":"t1","refund":"original","split":"single",
                  "preauth":"none","subscribe":"none","affiliate":"coupon","payout":"manual",
                  "kyc":"basic","tds":"optional","token":"network","device":"basic"},
    "gambling":  {"biz":"gambling","pay_method":"mixed","settle":"aggregator","currency":"multi",
                  "risk":"ml","recon":"t0","refund":"manual","split":"multi_level",
                  "preauth":"none","subscribe":"none","affiliate":"multi_tier","payout":"auto",
                  "kyc":"tiered","tds":"none","token":"custom","device":"advanced"},
    "wallet":    {"biz":"wallet","pay_method":"bank_transfer","settle":"direct","currency":"multi",
                  "risk":"ml","recon":"realtime","refund":"wallet","split":"none",
                  "preauth":"none","subscribe":"none","affiliate":"points","payout":"auto",
                  "kyc":"tiered","tds":"none","token":"none","device":"advanced"},
    "indie":     {"biz":"indie","pay_method":"card","settle":"pg","currency":"single",
                  "risk":"none","recon":"none","refund":"manual","split":"none",
                  "preauth":"none","subscribe":"none","affiliate":"none","payout":"manual",
                  "kyc":"none","tds":"optional","token":"network","device":"none"},
    "remittance":{"biz":"remittance","pay_method":"bank_transfer","settle":"direct","currency":"dcc",
                  "risk":"rules","recon":"t1","refund":"original","split":"none",
                  "preauth":"none","subscribe":"none","affiliate":"none","payout":"hybrid",
                  "kyc":"full","tds":"none","token":"none","device":"basic"},
}

def assess(p):
    hits = []
    for cond, rid, title, impact, how, poc in RULES:
        try:
            if cond(p):
                sev = SEVERITY.get(rid[0], ("⚪ 其他", 5))
                hits.append({"id": rid, "level": sev[0], "prio": sev[1],
                             "title": title, "impact": impact,
                             "how": how, "poc": poc})
        except Exception:
            pass
    hits.sort(key=lambda x: (x["prio"], x["id"]))
    return hits

def main():
    ap = argparse.ArgumentParser(description="支付系统攻击面评估器")
    ap.add_argument("--preset", choices=list(PRESETS))
    ap.add_argument("--profile")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.profile:
        with open(a.profile, encoding="utf-8") as f:
            p = json.load(f)
    elif a.preset:
        p = PRESETS[a.preset]
    else:
        print("可用预设：" + ", ".join(PRESETS))
        print("或 --profile xxx.json")
        return 1

    hits = assess(p)
    if a.json:
        print(json.dumps({"profile": p, "findings": hits}, ensure_ascii=False, indent=2))
        return 0

    print("=" * 78)
    print("  支付系统攻击面评估")
    print("=" * 78)
    print(f"\n[画像]")
    for k, (name, _vals) in FIELDS.items():
        print(f"  {name:<12}{p.get(k, '?')}")

    print(f"\n[命中 {len(hits)} 项，按优先级]")
    cur = None
    for h in hits:
        if h["level"] != cur:
            cur = h["level"]
            print(f"\n  {cur} 类")
        print(f"    [{h['id']}] {h['title']}")
        print(f"         影响：{h['impact']}")
        print(f"         怎么测：{h['how']}")
        print(f"         PoC：{h['poc']}")

    print("\n" + "=" * 78)
    print("  下一步")
    print("=" * 78)
    top = [h for h in hits if h["prio"] <= 2][:5]
    print("  先做这 %d 个（资金/计费/认证类）：" % len(top))
    for i, h in enumerate(top, 1):
        print(f"    {i}. {h['title']}  →  {h['poc']}")
    print("\n  每条 PoC 都是本地靶场，改目标地址就能验证。")
    print("=" * 78)
    return 0

if __name__ == "__main__":
    sys.exit(main())
