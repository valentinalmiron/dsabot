export function getWebhookData (req, HEADEREVENT, HEADERCONTENTTYPE ) {
        const data = {
        action: req.body.action,
        state: req.body.pull_request.state,
        base: req.body.pull_request.base.ref,
        merged: req.body.pull_request.merged.toString(),
        jsonData: req.body,
        number: req.body.number,
        urlRepository: req.body.repository.html_url,
        nameRepository: req.body.repository.name,
        event: req.header(HEADEREVENT),
        contentType: req.header(HEADERCONTENTTYPE)
        };
        return data;
}