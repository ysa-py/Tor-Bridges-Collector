#!/usr/bin/env bash
# close-stale-prs.sh
#
# هدف: بستن PR های Open قدیمی و حذف برنچ مربوطه — بدون هیچ تاثیری روی کد/قابلیت‌های پروژه.
# فقط از GitHub API (gh CLI) استفاده می‌کنه، هیچ فایلی توی رپو دست نمی‌خوره.
#
# استفاده:
#   ./close-stale-prs.sh                     # dry-run روی رپوی فعلی، آستانه ۳۰ روز
#   DAYS_OLD=14 ./close-stale-prs.sh          # آستانه سفارشی
#   DRY_RUN=false ./close-stale-prs.sh        # اجرای واقعی (حذف/بستن)
#   REPO=owner/repo ./close-stale-prs.sh      # رپوی مشخص (پیش‌فرض: رپوی فعلی)
#
# پیش‌نیاز: gh CLI نصب و لاگین باشه (gh auth login) — توی Codespaces معمولاً پیش‌فرضه.

set -euo pipefail

DAYS_OLD="${DAYS_OLD:-30}"
DRY_RUN="${DRY_RUN:-true}"
REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
SKIP_LABELS="${SKIP_LABELS:-keep-open,do-not-close,pinned}"
DEFAULT_BRANCH="$(gh repo view "$REPO" --json defaultBranchRef -q .defaultBranchRef.name)"

echo "================================================================"
echo " رپو:                 $REPO"
echo " آستانه‌ی قدیمی بودن:  $DAYS_OLD روز"
echo " حالت اجرا:            $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (فقط نمایش)" || echo "اجرای واقعی")"
echo " لیبل‌های محافظت‌شده:  $SKIP_LABELS"
echo " برنچ default:         $DEFAULT_BRANCH (هیچوقت حذف نمی‌شه)"
echo "================================================================"

cutoff_epoch=$(date -u -d "-${DAYS_OLD} days" +%s 2>/dev/null || date -u -v-"${DAYS_OLD}"d +%s)

closed_count=0
skipped_count=0
branch_deleted_count=0

IFS=',' read -ra SKIP_LABEL_ARR <<< "$SKIP_LABELS"

prs_json="$(gh pr list --repo "$REPO" --state open --limit 1000 \
  --json number,title,createdAt,headRefName,isCrossRepository,labels)"

pr_count="$(jq 'length' <<< "$prs_json")"

if [ "$pr_count" -eq 0 ]; then
  echo "هیچ PR باز (open) توی این رپو نیست. کاری برای انجام نبود."
  echo "================================================================"
  exit 0
fi

echo " تعداد PR های باز پیدا شده:  $pr_count"
echo "================================================================"

while read -r pr; do

  number=$(jq -r '.number' <<< "$pr")
  title=$(jq -r '.title' <<< "$pr")
  createdAt=$(jq -r '.createdAt' <<< "$pr")
  headRef=$(jq -r '.headRefName' <<< "$pr")
  isFork=$(jq -r '.isCrossRepository' <<< "$pr")
  labels=$(jq -r '[.labels[].name] | join(",")' <<< "$pr")

  created_epoch=$(date -u -d "$createdAt" +%s 2>/dev/null || date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$createdAt" +%s)

  # رد کردن PR های تازه
  if [ "$created_epoch" -gt "$cutoff_epoch" ]; then
    continue
  fi

  # رد کردن PR های محافظت‌شده با لیبل
  skip=false
  for lbl in "${SKIP_LABEL_ARR[@]}"; do
    if [[ ",$labels," == *",$lbl,"* ]]; then
      skip=true
      break
    fi
  done
  if [ "$skip" = true ]; then
    echo "⏭️  رد شد (لیبل محافظت‌شده) — PR #$number: $title"
    skipped_count=$((skipped_count + 1))
    continue
  fi

  # هیچوقت به برنچ default دست نمی‌زنیم
  if [ "$headRef" = "$DEFAULT_BRANCH" ]; then
    echo "⏭️  رد شد (برنچ default) — PR #$number"
    skipped_count=$((skipped_count + 1))
    continue
  fi

  echo "🔴 PR #$number قدیمیه ($createdAt) — برنچ: $headRef — $title"

  if [ "$DRY_RUN" = "true" ]; then
    echo "   [dry-run] این PR بسته و برنچش حذف می‌شد."
    closed_count=$((closed_count + 1))
    continue
  fi

  gh pr close "$number" --repo "$REPO" \
    --comment "این PR به دلیل عدم فعالیت بیش از ${DAYS_OLD} روز به‌صورت خودکار بسته شد."
  closed_count=$((closed_count + 1))

  if [ "$isFork" = "false" ]; then
    if gh api -X DELETE "repos/$REPO/git/refs/heads/$headRef" >/dev/null 2>&1; then
      echo "   ✅ بسته شد و برنچ حذف شد."
      branch_deleted_count=$((branch_deleted_count + 1))
    else
      echo "   ⚠️ بسته شد، ولی حذف برنچ ناموفق بود (شاید قبلاً حذف شده)."
    fi
  else
    echo "   ✅ بسته شد. (برنچ توی فورک خارجیه، حذف نشد)"
  fi

done < <(jq -c '.[]' <<< "$prs_json")

echo "================================================================"
echo " خلاصه:"
echo "   PR های بسته‌شده:        $closed_count"
echo "   برنچ‌های حذف‌شده:       $branch_deleted_count"
echo "   PR های رد‌شده (محافظت‌شده): $skipped_count"
echo "================================================================"
echo "تمام شد."
