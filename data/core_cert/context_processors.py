from .models import GlobalSetting
from datetime import datetime, timedelta
from django.utils import timezone

def global_settings(request):
    settings_dict = {s.key: s.value for s in GlobalSetting.objects.all()}
    acmedns_base_url = settings_dict.get('ACMEDNS_BASE_URL')
    
    # 다음 실행까지 남은 시간 계산
    renewal_time_str = settings_dict.get('RENEWAL_TIME', '03:00')
    time_remaining = "계산 중..."
    try:
        now = timezone.localtime(timezone.now())
        target_time_obj = datetime.strptime(renewal_time_str.strip(), '%H:%M').time()
        
        # 1. 현재 시각과 설정 시각의 '시:분'이 같은지 확인
        if now.hour == target_time_obj.hour and now.minute == target_time_obj.minute:
            time_remaining = "작업 수행 중 (1분 이내)"
        else:
            # 2. 오늘 날짜로 목표 일시 생성
            target_dt = timezone.make_aware(datetime.combine(now.date(), target_time_obj))
            
            # 3. 만약 목표 시간이 이미 지났다면 내일로 설정
            if target_dt < now:
                target_dt += timedelta(days=1)
                
            # 4. 남은 시간 계산 (항상 양수가 나옴)
            diff = target_dt - now
            seconds = int(diff.total_seconds())
            hours, remainder = divmod(seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            
            time_remaining = f"{hours}시간 {minutes}분 남음"
    except Exception:
        time_remaining = "형식 오류 (HH:MM)"
    
    return {
        'global_settings': settings_dict,
        'ACMEDNS_BASE_URL': acmedns_base_url,
        'acmedns_setup_needed': not bool(acmedns_base_url),
        'next_renewal_remaining': time_remaining
    }
