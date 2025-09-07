document.addEventListener('DOMContentLoaded', function () {
    const startBtn = document.getElementById('start-import');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');

    startBtn.addEventListener('click', function () {
        startBtn.disabled = true;
        progressContainer.style.display = 'block';

        fetch('/import-json/process', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let progress = 0;
                const interval = setInterval(function () {
                    if (progress >= 100) {
                        clearInterval(interval);
                        setTimeout(() => {
                            window.location.href = "/";
                        }, 1000);
                    } else {
                        progress += 5;
                        progressBar.style.width = progress + "%";
                        progressBar.innerText = progress + "%";
                    }
                }, 100);
            } else {
                alert('Hata: ' + data.message);
                window.location.reload();
            }
        })
        .catch(err => {
            alert('Sunucu hatası.');
            window.location.reload();
        });
    });
});
