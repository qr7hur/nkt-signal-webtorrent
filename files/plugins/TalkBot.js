$.plugin({
	name: 'TalkBot',
    
    onWrite: function(msg, nick) {
        return this.TalkBot(msg, true, nick);
    },
    
    
    TalkBot: function(msg, tags, nick) {
		var LoFArray = ["De quoi ?","Nan mais les entreprises, elles, un mois c'est pas assez, elles veulent 4 semaines, 8 semaines...","La porte de ma chambre je la ferme que quand je suis dedans","Y'a de quoi s'embrocher la barbaque là","Le stage c'était bien du 6 mars au 2 février?","Non mais d'ailleurs mon urine est assez floue en ce moment (mais sans le contexte c'est nul...)","Les vingt premières minutes de la fin","Fais gaffe les murs ont des oreilles, ils ont peut-être des mains aussi !","Oh putain! Il a essayé de m enfiloter !","Et, avec la participation d un certain ND à moitié arménien que je ne citerai pas","FD -Mais t imagines le paradoxe de la gravité? Gras et vite ! *blanc* ND - C était un flop là... FD - Oui un beau flop j ai un brelan de rois maintenant.","J préfère encore la cabane photo","JA -Nan mais à ce prix là, y a forcément un processeur de merde...FD -Pas forcément de merde mais performant","Dans un McDonald : Je voudrais un menu Maxi Best-Of avec Frites et Potatoes.","Devant son balcon attaqué par des pigeons : Ils ont chié partout! Ils ont chié ici! Ils ont chié là! Ils ont chié partout! Ah les enculés ils ont chié partout!","C est plus Linkin Park, c est Fuckin Park","Non mais pour moi, la journée de demain commence aujourd hui.","Je vais t écraser le crâne sur la gueule","Mon père c est pas un singe mais il est poilu quand même","Tiens le caviar ça a un goût de fromage. Mais ça doit être à cause du pain"," -Boite de Pandore ou poule aux oeufs d or?-En tout cas j ai pas dit boîte aux oeufs d or","Fabien, sur la sécurité des systèmes embarqués :Semi-intrusif c est Je te mets à poil et intrusif c est Je te fous un thermomètre dans le cul","Ca sert à rien de réinventer la poudre, elle est déjà faite..."];
        if (msg.charAt(0) != '/' && (!tags || (tags && nick))) {
            if(msg.indexOf("oulas") > -1)
				setTimeout(function(){
					$.chat.write( LoFArray[Math.floor(Math.random() * LoFArray.length)], 'Daoulas');
				}, 500);
        }
        
        return msg;
    }
});
