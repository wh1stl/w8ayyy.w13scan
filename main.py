import levrt
from lev.w8ayyy.w13scan.w13scan import spider,single_scan,fullscan

async def main():
    # doc = await spider(max_count=10086, thread_num=20, url="http://testphp.vulnweb.com", cookies="w13scan=1;")
    # doc = await single_scan("http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12",cookies="w13scan=1;",threads=30)
    doc = await fullscan("http://testphp.vulnweb.com")
    data = await doc.get()
    print(data)


if __name__ == "__main__":
    levrt.run(main())
