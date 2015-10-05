package me.itzg.es.auth;

import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.assertNotNull;

/**
 * @author Geoff Bourne
 * @since 10/3/2015
 */
public class AuthenticatingTransportServiceTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private Node node;
    private int port;

    @Before
    public void setUp() throws Exception {
        final File dataFolder = temporaryFolder.newFolder();
        final File confFolder = temporaryFolder.newFolder();

        Files.copy(this.getClass().getClassLoader().getResourceAsStream("elasticsearch-jaas.conf"),
                Paths.get(confFolder.toURI()).resolve("elasticsearch-jaas.conf"));

        node = NodeBuilder.nodeBuilder()
                .settings(ImmutableSettings.settingsBuilder()
                                .put("path.data", dataFolder)
                                .put("path.conf", confFolder)
                                .put("transport.host", "localhost")
                                .put("transport.tcp.port", 0)
                                .put("http.enabled", false)
                                .put(AuthenticatingTransportService.SETTING_INCOMING_REQUIRE_AUTH, true)
                                .put(AuthenticatingTransportService.SETTING_REMOTE_IDENTIFIER, "user-1")
                                .put(AuthenticatingTransportService.SETTING_REMOTE_CREDENTIAL, "pass-1")
                                .put(AuthenticatingTransportService.SETTING_INCOMING_AUTH_TYPE, AuthenticatingTransportService.AUTH_TYPE_IN_MEMORY)
                )
                .build()
                .start();

        final NodesInfoResponse nodeInfos = node.client().admin().cluster().prepareNodesInfo()
                .setTransport(true)
                .get();

        final InetSocketTransportAddress transportAddress =
                (InetSocketTransportAddress) nodeInfos.getAt(0).getTransport().getAddress().boundAddress();

        port = transportAddress.address().getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (node != null) {
            node.close();
        }
    }

    @Test
    public void testDoStart() throws Exception {
        final ImmutableSettings.Builder settings = ImmutableSettings.settingsBuilder()
                .put(AuthenticatingTransportService.SETTING_REMOTE_IDENTIFIER, "user-1")
                .put(AuthenticatingTransportService.SETTING_REMOTE_CREDENTIAL, "pass-1");

        final TransportClient transportClient = new TransportClient(settings);
        transportClient.addTransportAddress(new InetSocketTransportAddress("localhost", port));

        final IndexResponse indexResponse = transportClient.prepareIndex("test-index", "test-type")
                .setId("test-id")
                .setSource("field-1", "value-1")
                .get();

        final SearchResponse searchResponse = transportClient.prepareSearch().setSize(0).get();
        assertNotNull(searchResponse);
    }
}