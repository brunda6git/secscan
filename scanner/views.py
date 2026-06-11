# from django.shortcuts import render
# Create your views here.

import json
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ScanResult
from .security_checks import run_scan
from .report_generator import generate_report


def index(request):
    query = request.GET.get('q', '')
    if query:
        recent = ScanResult.objects.filter(url__icontains=query)[:20]
    else:
        recent = ScanResult.objects.all()[:10]
    return render(request, 'scanner/index.html', {'recent': recent, 'query': query})


@csrf_exempt
def scan(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)
    try:
        body = json.loads(request.body)
        url = body.get('url', '').strip()
        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)

        result = run_scan(url)

        saved = ScanResult.objects.create(
            url=result['url'],
            score=result['score'],
            risk_level=result['risk_level'],
            results_json=json.dumps(result),
        )
        result['scan_id'] = saved.id
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def download_report(request, scan_id):
    try:
        scan = ScanResult.objects.get(id=scan_id)
        data = scan.get_results()
        pdf = generate_report(data)
        response = HttpResponse(pdf, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="scan_report.pdf"'
        return response
    except ScanResult.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
