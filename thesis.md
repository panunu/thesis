# AUTOMAATTINEN KESKUSTELUN VISUALISOINTI

* Puppugeneraattorin käynnistys
* Johdanto
* Keskustelijoiden vuorovaikutus keskusteluun ja toisiinsa
* Nykyiset palaverikäytännöt ja ongelmakohdat
* Automaattinen litterointi - tulevaisuus
* Tekninen toteutus ja tietorakenteet
* Keskustelijoiden pisteyttäminen, "gamification"
* Keskustelukulun visualisointi
* Keskustelun yhteenveto
* Tulosten todentaminen ja jatkokehitys
* Tiivistelmä

# Johdanto

Tavoitteena on selvittää, voiko keskustelun automaattisesta visualisoinnista ja yhteenvedosta olla hyötyä keskustelun kokonaisuuden hahmottamisen suhteen. Samalla todennetaan insinöörityössä hyödynnettävän Juju-ohjelmiston käyttökelpoisuus.

# Keskustelijoiden vuorovaikutus keskusteluun ja toisiinsa

Keskustelun osalliset ja heidän väliset suhteet vaikuttavat keskustelun kulkuun ja lopputulokseen. 
...

Auttaako visualisointi dialektiikan eli keskinäisviestinnän todentamisessa? Puhuvatko siis ihmiset samoista asioista, vai jauhavat omiaan sivuuttaen keskustelukumppanin sanoman?

Kenen aloittamista aiheista puhutaan? Kenellä on ollut valtaa ohjata keskustelun kulkua? Kuka puhuu omista aiheistaan, kuka toistelee aikaisemman keskustelun muovaamia teemoja?

# ?????

Jos nähdään, mitä aiheita esimerkiksi palaverin aikana on käsitelty ja samalla kerätään huomioita, mitä asioita palaverin ansiosta on päätetty, voidaan mahdollisesti useamman palaverin jälkeen alkaa muodostaa mielikuvaa siitä, käsitelläänkö samaa aihetta useissa palavereissa saamatta aikaan mitään konkreettista. Näin voidaan nostaa esille mahdollisesti hankalat päätökset ja korottaa niiden painoarvoa seuraavassa käsittelyssä.

# Automaattinen litterointi - tulevaisuus

Palavereissa, asiakastapaamisissa ja vastaavissa tilaisuuksissa vähintään yhden osallistujan kannattaa ottaa sihteerin rooli. Tämä tarkoittaa sitä, että hänen mahdollisuutensa osallistua keskusteluun vähenee merkittäväksi. Varsinkin pienemmässä projektiryhmässä yhden henkilön irroittaminen kyseiseen tehtävään ei aina ole mahdollista. Tunnetusti ihminen ei ole tehokas suorittamaan useita tehtäviä samanaikaisesti [http://www.pashler.com/Articles/Pashler_PB1994.pdf]. Tämä saattaa johtaa siihen, ettei palaverin aikana kirjoitetun muistion laatu vastaa aina haluttua.

Yksi ratkaisuvaihtoehto on keskustelun äänittäminen muistiin, jolloin mikään käsitelty asia ei jäisi kirjaamatta. Näin vältettäisiin myös mahdolliset kiistatilanteet palaverin aikana tehdyissä suullisissa sopimuksissa. Ratkaisu on kuitenkin kömpelö, eikä soveltuisi varsinkaan pitkäkestoisiin keskusteluihin, koska nauhoituksen läpikäyminen jälkikäteen esimerkiksi yhteenvedon kirjoittamista varten veisi aikaa. Toiseksi voisi olla työlästä hahmottaa kuka vuorollaan on ollut äänessä, johtaen mahdollisiin väärinkäsityksiin.

Parempi ratkaisu tähän tilanteeseen voisi olla automaattinen litterointi. Puhe siis muutettaisiin automaattisesti tekstimuotoon. Automaatiolla vältettäisiin manuaalisen litteroinnin tulkinnanvaraisuudet.

Jatkuvan puheen muuttamiseksi tekstiksi on olemassa jo valmiita sovelluksia, esimerkiksi Nuance Communicationsin Dragon Dictation. Valitettavasti ongelmaksi muodostuu vielä toistaiseksi teknologian kehittymättömyys, joka johtaa  virhealttiuteen. Suurin osa varsinkin suomenkielisestä sovellustarjonnasta keskittyy yksinkertaiseen puheentunnistukseen, jota voidaan hyödyntää esimerkiksi puheohjauksessa. Tällainen sovellus on tehty tunnistamaan ennaltamääriteltyjä, usein yksiosaisia komentoja. Dragon Dictation -tuoteperheen englanninkielistä palvelinpuolen sovellusta olisi voitu hyödyntää insinöörityössä, mutta tiedon eristämisen koneisto, Juju, prosessoi ainoastaan suomenkieltä. Näin ollen automaattinen litterointi jää toistaiseksi teoriatasolle.

Kuvitellaan kuitenkin automaattisen litteroinnin olevan mahdollista. Jotta tallenteen analysointi olisi mielekästä keskustelun näkökulmasta, puheenvuoroihin pitäisi liittää identiteettitieto. Toistaiseksi tarvittavaa teknologiaa, joka puheen lisäksi tunnistaisi puhujan identiteetin luotettavasti, ei ole olemassa [SELVITÄ], joten tämä pitäisi korvata yksinkertaisemmalla ratkaisulla. Teknisesti helposti toteutettava vaihtoehto olisi jakaa keskustelun osallisille henkilökohtaiset mikrofonit. Mikrofoneihin liitettäisiin puhujan henkilöllisyys joko etu- tai jälkikäteen. Tämä helpottaisi huomattavasti keskustelun etenemisen hahmottamista.

Edellämainitun ratkaisun avulla pystyisimme keräämään keskustelusta taulukossa [TAULUKKO] esitetyn formaatin mukaista dataa. Järjestelmä olettaa, että saatavissa oleva aineisto on kyseisessä muodossa.

aika, henkilö, puheenvuoro
aika, henkilö, puheenvuoro
aika, henkilö, puheenvuoro.

# Tekninen toteutus

Järjestelmän tekninen toteutus on joustavuuden nimissä jaettu selkeästi kahteen osaan: prosessointityökaluun ja käyttöliittymään. Tämä mahdollistaa prosessointityökalun hyödyntämisen erillisissä palveluissa ilman, että se on sidottu mihinkään valmiiseen käyttöliittymään. Rakenne on esitetty kuvassa [KUVA].

## Järjestelmien välinen viestintä

Järjestelmän prosessointityökalu ja käyttöliittymä on toteutettu eri teknologioilla: Scala ja PHP.

Viestit välitetään järjestelmästä toiseen eri muodoissa. Ne käsitellään Base64-koodauksella riippumatta viestin kulkusuunnasta. Tarkoituksena on välttää mahdolliset merkistöongelmat. Lähettävä osapuoli enkoodaa? viestin, ja vastaanottaja dekoodaa? sen.

Käyttöliittymä lähettää palveluun ladatun CSV-tiedoston sisällön prosessointityökalulle. Tiedoston sisältöä ei vielä tässä vaiheessa prosessoida mitenkään, lukuunottamatta kuitenkaan enkoodausta?.

Prosessointityökalu rakentaa viestijonon kautta saadusta CSV-materiaalista JSON-formaatin mukaista dataa. Tämä välitetään takaisin käyttöliittymäohjelmistolle tallennettavaksi tietokantaan.

### Asynkroninen viestijonoprotokolla

## Prosessointi

Prosessointityökalu pyörii ajastetusti tausta-ajona. Se on toteutettu hyödyntäen seuraavia teknologioita:

- Scala
- Java
- Akka.

### Scala

Scala on ohjelmointikieli, joka yhdistää kaksi tekijää yhteen, jotka yleensä nimenomaan erottavat kieliä toisistaan; olio-ohjelmoinnin ja funktionaalisen ohjelmoinnin.  
[Scala By Example, Martin Odersky, 2011]

Koska Scala toimii JVM:n päällä, sillä on mahdollista käyttää muilla JVM-yhteensopivilla ohjelmointikielillä toteutettuja ohjelmia. Tämän ansiosta Jujun käyttöönotto projektissa on helppoa.

### MongoDB

Prosessointi höydyntää E-Reading -hankkeen yhteydessä toteutettua Juju-koneistoa ja sitä sovelletaan entiteettien tunnistamiseen ja avainsanojen poimintaan. Työn aikana oli myös tarkoitus todentaa koneiston käyttökelpoisuus ulkopuolisen näkökulmasta. Samalla oli mahdollisuus vaikuttaa ohjelmiston rajapinnan, dokumentaation ja sen kehittämiseen liittyvien käytäntöjen kehitykseen.

## Visualisointi

...

# Keskustelijoiden pisteyttäminen, "Gamification"

Keskustelun pisteyttämisen ydintarkoitus on saada nopeasti karkea kuva osallistujien aktiivisuudesta ja puheenvuorojen laadukkuudesta. Pisteytys perustuu aina puheenvuoroon ja sen välisiin suhteisiin. Pisteitä saa esimerkiksi mainitsemalla uuden käsitteen keskustelun aikana.

Tämän lisäksi pisteyttämisen tuomalla "porkkanalla" voisi aktivoida osallistujia mukaan keskusteluun. Kyseinen ajatus liittyy Gamification-ajatusmalliin. Gamificationin perusidea on se, että pyritään tuomaan esimerkiksi videopeleistä tuttuja elementtejä arkipäivän rutiineihin, tarkoituksena motivoida työntekijää suoriutumaan tehtävistään.

Gamificationissa on myös mahdolliset haittapuolensa. Jos pisteytykselle annetaan liikaa painoarvoa, keskustelun osalliset saattavat keskittyä liikaa pisteiden keräämiseen. Tämä taas ohjaa pois laadukkaasta keskustelusta. Pisteytys on ulkoinen motivaation lähde, joka ei tuo mitään lisäarvoa itse keskusteluun. [The Dangers of Gamification, Krystle Jiang, 2011]

Mahdollisten riskien takia projektissa päädyttiin ratkaisuun, jossa pisteytystä ei ole yksityiskohtaisesti eroteltu tai korostettu. Sen sijaan pisteitä käytetään henkilön aktiivisuuden osoittamisen apuna.
...

# Tulosten todentaminen ja jatkokehitys

Eräs todella tärkeä osa kommunikaatiota on ilmaisun tyyli. Tällä tarkoitan esimerkiksi sitä, millä äänensävyllä asian ilmaisee. Keskustelun tulkitsemisessa tällä on iso rooli. Jos keskustelu vaikka muuttuu dramaattisesti, puhetyylistä voidaan saada osviittaa mahdollisesta syystä. Ilmaisuille on tehty oma merkintäkielensä, [SELVITÄ].

Tällä hetkellä sovellus pyrkii olemaan kohtuullisen yleispätevä erikoistumatta mihinkään tiettyyn keskusteluvariaatioon. Jatkossa ohjelmistoa voisi jatkokehittää erikoistumaan erilaisiin sovellutuksiin. Eräs idea olisi hahmottaa yksittäisten henkilöiden välisten suhteiden lisäksi vuorovaikutusta isommassa mittakaavassa. Tämä voitaisiin saavuttaa erilaisten tunnisteiden lisäämisellä käsiteltävään materiaaliin, esimerkiksi tässä tapauksessa henkilölle määriteltäisiin ryhmä, johon hän kuuluu. Näin voitaisiin esimerkiksi politiikan viitekehyksessä havaita, miten puolueiden väliset aihepiirit eroavat toisistaan.