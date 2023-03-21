---
title: Python notes
---

## Threading
```python
    from multiprocessing.dummy import Pool as ThreadPool

    def func():
        pass

    pool = ThreadPool(8)
    result = pool.map(func, args)
    pool.close()
    pool.join()
```

## Unpack
```

```

## Requests
```python
    import requests

    resp = requests.post(
        "http://test.com",
        data={ 'username': 'test' }
        cookies={ 'is_logged': 1 },
        headers={ 'X-Token': 'token' },
        proxies={ 'http': '127.0.0.1', 'https': '127.0.0.2' },
        allow_redirects=False,
        verify=False  # When error occurs with custom SSL certificate 
    )

    # Response properties
    resp.request
    resp.status_code
    resp.headers
    resp.cookies
    resp.text
    resp.json()
```

## Beautiful-soup
```

```