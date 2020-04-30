import wget
import os
import json
import shutil
from datetime import date
from zipfile import ZipFile

from django.http import JsonResponse
from django.shortcuts import render


def search_page(request):
    return render(request, 'vulner_search.html')


def search_vulner(request):
    try:
        os.mkdir(os.getcwd() + '/downloaded')
    except OSError:
        print("پوشه ی downloaded برای ذخیره ی اطلاعات خام در دسترس است")
    else:
        print("پوشه ی downloaded حاوی اطلاعات خام ایجاد شد")
    try:
        os.mkdir(os.getcwd() + '/output')
    except OSError:
        print("پوشه ی output برای ذخیره ی اطلاعات استخراج شده در دسترس است")
    else:
        print("پوشه ی output حاوی اطلاعات استخراج شده ایجاد شد")

    dl_name = os.getcwd() + '/downloaded/' + date.today().__str__()

    if os.path.isfile(dl_name + '.zip'):
        print("فایل حاوی اطلاعات خام قبلا دانلود شده است")
    else:
        print("در حال دانلود فایل")
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
        wget.download(url, dl_name + '.zip')
        print("دانلود تکمیل شد")

        with ZipFile(dl_name + '.zip', 'r') as zipObj:
            zipObj.extractall(os.getcwd() + '/downloaded')

        os.rename(os.getcwd() + '/downloaded/nvdcve-1.1-modified.json', dl_name + '.json')

    out_dir = os.getcwd() + '/output/' + date.today().__str__()
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
        print("داده های قبلی حذف شد و داده های جدید جایگزین شدند")
    try:
        os.mkdir(out_dir)
    except OSError:
        print("خطا در ایجاد پوشه ی امروز")
    else:
        print("پوشه ای  با نام تاریخ امروز برای ذخیره اطلاعات امروز ایجاد شد")

    with open(dl_name + '.json', 'r') as CVE_FILE:
        file = json.load(CVE_FILE)

    # begin_date = input(":تاریخ شروع جستجو را به فرم 15-04-2020 وارد کنید\n")
    begin_date = request.GET.get('query')
    results = []

    for item in file['CVE_Items']:
        try:
            if item['lastModifiedDate'][0:10] >= begin_date:
                under_impact = []
                for match in item['configurations']['nodes']:
                    for cpe in match['cpe_match']:
                        try:
                            under_impact.append(cpe['cpe23Uri'])
                        except:
                            pass
                refs = []
                for ref in item['cve']['references']['reference_data']:
                    refs.append("\n" + ref['url'])
                results.append(
                    [item['cve']['CVE_data_meta']['ID'], item['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                     '?',
                     item['impact']['baseMetricV3']['cvssV3']['baseScore'], item['publishedDate'][0:10],
                     item['lastModifiedDate'][0:10], under_impact,
                     item['cve']['description']['description_data'][0]['value'], refs])
        except:
            pass

    return render(request, 'vulners_results.html', context={'results': results})
