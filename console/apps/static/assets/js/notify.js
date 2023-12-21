
const socket = new WebSocket('ws://' + window.location.host + window.location.pathname)

socket.onopen = function() {
    console.log('ws connection success');
};


const notification_template = `
<a href="/alerts" class="list-group-item m-1 list-group-item-action">
  <div class="row align-items-center">
    <div class="col ml--2">
      <div class="d-flex justify-content-between align-items-center">
        <div>
          <h4 class="text">
            <i class="ni ni-notification-70 text-danger"></i>
            <span class="text-lg bg-{{color}}">
            {{source}}
            </span>
            <i class="ni ni-bold-right text-dark"></i>
            <span class="text-lg bg-secondary">
            {{destination}}
            </span>
          </h4>
            <small class="text-sm text-dark"> {{datetime}} </small>
        </div>
      </div>
      <!--p class="text-sm mb-0"> {{description}} </p-->
    </div>
  </div>
</a>
`

const notification_button = document.getElementById("notification-dropdown");
const colors = ["yellow", "warning", "cyan", "info", "orange"]

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    const notification_item = notification_template
        .replace("{{source}}", data.source)
        .replace("{{destination}}", data.destination)
        .replace("{{description}}", data.description)
        .replace("{{datetime}}", Date(data.datetime))
        .replace("{{color}}", colors[Math.floor(Math.random() * colors.length)])

    document.getElementById("notifications").innerHTML = notification_item
        + document.getElementById("notifications").innerHTML;

    document.getElementById("notifications-list").innerHTML = notification_item
        + document.getElementById("notifications-list").innerHTML;

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

