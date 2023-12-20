
const socket = new WebSocket('ws://' + window.location.host + window.location.pathname)

socket.onopen = function() {
    console.log('ws connection success');
};


const notification_template = `
<a href="/alerts" class="list-group-item list-group-item-action">
    <div class="row align-items-center">
        <div class="col ml--2">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <i class="ni ni-notification-70 text-danger"></i>
                <span class="nav-link-text"> {{source}} </span>
            </div>
            <div class="text-right text-muted">
                <small> {{timestamp}} </small>
            </div>
        </div>
        <p class="text-sm mb-0"> {{description}} </p>
        </div>
    </div>
</a>
`

const notification_button = document.getElementById("notification-dropdown");

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    document.getElementById("notifications").innerHTML =
        notification_template
            .replace("{{source}}", data.source_ip)
            .replace("{{description}}", data.description)
            .replace("{{timestamp}}", data.timestamp)
        + document.getElementById("notifications").innerHTML;

    if (notification_button.parentElement.classList.contains("show") == false) {
        notification_button.click();
    }

    console.log(data);
};

socket.onclose = function(event) {
    console.log('connection close');
};

socket.onerror = function(error) {
    console.error('error:', error);
};

